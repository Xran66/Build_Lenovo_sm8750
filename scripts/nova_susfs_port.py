#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 SUSFS 接进 SukiSU-Nova（最小侵入，不动 Nova 的 supercall 架构）。

背景：
  simonpunk 的 kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch 是一次架构级替换
  （32 个文件，会删掉 Nova 的 ksu_late_loaded / ksu_bundled / hook/*.o），并且它的
  kernel/supercall/dispatch.c 段落与 Nova 现行实现冲突 —— 而那个文件正是 KPM supercall 的宿主。
  所以不复用整份补丁，只取真正缺的三块：

  1) kernel/Kconfig          加 SUSFS 配置菜单（否则 CONFIG_KSU_SUSFS* 是未知符号，
                             defconfig 里写了也会被 make 丢掉，内核里所有 SUSFS 代码
                             都因为 #ifdef 不成立而不编译）
  2) kernel/core/init.c      调 susfs_init()
  3) kernel/supercall/dispatch.c
                             加 ksu_handle_sys_reboot()：ksud 的 susfs 命令走
                             reboot(2) + KSU_INSTALL_MAGIC1 + SUSFS_MAGIC，
                             接收端就是它。内核侧 kernel/reboot.c 的分发已经由
                             50_add_susfs_in_*.patch 装好，只等这个函数存在。

用法: nova_susfs_port.py <KernelSU 仓库根目录>
"""
import io
import os
import sys

SUSFS_KCONFIG = r"""menu "KernelSU - SUSFS"
config KSU_SUSFS
	bool "KernelSU addon - SUSFS"
	depends on KSU
	depends on THREAD_INFO_IN_TASK
	default y
	help
	  Patch and Enable SUSFS to kernel with KernelSU.

config KSU_SUSFS_SUS_PATH
	bool "Enable to hide suspicious path"
	depends on KSU_SUSFS
	default y
	help
	  - Allow hiding the user-defined path and all its sub-paths from various system calls.
	  - Use "add_sus_path_loop" instead of "add_sus_path" if the user-defined path is frequently modified.
	  - Use with cautious as it may cause performance loss and will be vulnerable to side channel attacks,
	  	just disable this feature if it doesn't work for you or you don't need it at all.
	  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.

config KSU_SUSFS_SUS_MOUNT
	bool "Enable to hide suspicious mounts"
	depends on KSU_SUSFS
	default y
	help
	  - Automatically assign fake mnt_id and fake mnt_group_id for mounts mounted by ksu process until
	    /sdcard is  decrypted, this is to evade from mnt_id/mnt_group_id gap detections.
	  - Allow hiding all sus mounts from /proc/self/[mounts|mountinfo|mountstat] for non-su processes.
	  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED.

config KSU_SUSFS_SUS_KSTAT
	bool "Enable to spoof suspicious kstat"
	depends on KSU_SUSFS
	default y
	help
	  - Allow spoofing the kstat of user-defined file/directory.
	  - Effective on all processes with (uid % 100000) >= 10000.

config KSU_SUSFS_SPOOF_UNAME
	bool "Enable to spoof uname"
	depends on KSU_SUSFS
	default y
	help
	  - Allow spoofing the string returned by uname syscall to user-defined string.
	  - Effective on all processes.

config KSU_SUSFS_ENABLE_LOG
	bool "Enable logging susfs log to kernel"
	depends on KSU_SUSFS
	default y
	help
	  - Allow logging susfs log to kernel, uncheck it to completely disable all susfs log.

config KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	bool "Enable to automatically hide ksu and susfs symbols from /proc/kallsyms"
	depends on KSU_SUSFS
	default y
	help
	  - Automatically hide ksu and susfs symbols from '/proc/kallsyms'.
	  - Effective on all processes.

config KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	bool "Enable to spoof /proc/bootconfig (gki) or /proc/cmdline (non-gki)"
	depends on KSU_SUSFS
	default y
	help
	  - Spoof the output of /proc/bootconfig (gki) or /proc/cmdline (non-gki) with a user-defined file.
	  - Effective on all processes.

config KSU_SUSFS_OPEN_REDIRECT
	bool "Enable to redirect a path to be opened with another path"
	depends on KSU_SUSFS
	default y
	help
	  - Allow redirecting a target path to be opened with another user-defined path.
	  - Both target path and redirected path must be existed before they can be added to the kernel.
	  - Users have to take care of the selinux permission of both target path and redirected path by themselves.
	  - OPEN_REDIRECT does not bypass some detections by default, but users can work with SUS_KSTAT to bypass them.
	  - Effective only on processes with pre-defined uid scheme.

config KSU_SUSFS_SUS_MAP
	bool "Enable to hide some mmapped real file from different proc maps interfaces"
	depends on KSU_SUSFS
	default y
	help
	  - Allow hiding mmapped real file from /proc/<pid>/[maps|smaps|smaps_rollup|map_files|mem|pagemap]
	  - It does NOT support hiding for anon memory.
	  - It does NOT hide any inline hooks or plt hooks cause by the injected library itself.
	  - It may not be able to evade detections by apps that implement a good injection detection.
	  - Effective only on zygote/zygote_next spawned user app process that is marked with TIF_PROC_UMOUNTED
	    and with (uid % 100000) >= 10000.

config KSU_SUSFS_PRIORITY_UID_FILTER
	bool "Enable to allow adding user-defined uids that will be hidden from getpriority/setpriority/ioprio_get/ioprio_set syscall"
	depends on KSU_SUSFS
	default y
	help
	  - Allow hiding user-defined uids from syscalls like getpriority/setpriority/ioprio_get/ioprio_set.
	  - Effective on all processes with uid >= 10000.

endmenu
"""

SUSFS_DISPATCH = r"""int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
    if (magic1 != KSU_INSTALL_MAGIC1) {
        return -EINVAL; 
    }

    // If magic2 is susfs and current process is root
    if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
        switch(cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
            case CMD_SUSFS_ADD_SUS_PATH:
                susfs_add_sus_path(arg);
                return 0;
            case CMD_SUSFS_ADD_SUS_PATH_LOOP:
                susfs_add_sus_path_loop(arg);
                return 0;
            case CMD_SUSFS_SET_SUS_PATH_UID_FILTER:
                susfs_set_sus_path_uid_filter(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
            case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
                susfs_set_hide_sus_mnts_for_non_su_procs(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
            case CMD_SUSFS_ADD_SUS_KSTAT:
                susfs_add_sus_kstat(arg);
                return 0;
            case CMD_SUSFS_UPDATE_SUS_KSTAT:
                susfs_update_sus_kstat(arg);
                return 0;
            case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
                susfs_add_sus_kstat(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
            case CMD_SUSFS_SET_UNAME:
                susfs_set_uname(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
            case CMD_SUSFS_ENABLE_LOG:
                susfs_enable_log(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
            case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
                susfs_set_cmdline_or_bootconfig(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
            case CMD_SUSFS_ADD_OPEN_REDIRECT:
                susfs_add_open_redirect(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
            case CMD_SUSFS_ADD_SUS_MAP:
                susfs_add_sus_map(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER
            case CMD_SUSFS_SET_PRIORITY_UID_FILTER:
                susfs_set_priority_uid_filter(arg);
                return 0;
#endif // #ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER
            case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
                susfs_set_avc_log_spoofing(arg);
                return 0;
            case CMD_SUSFS_SHOW_ENABLED_FEATURES:
                susfs_get_enabled_features(arg);
                return 0;
            case CMD_SUSFS_SHOW_VARIANT:
                susfs_show_variant(arg);
                return 0;
            case CMD_SUSFS_SHOW_VERSION:
                susfs_show_version(arg);
                return 0;
            default:
                return -EINVAL;
        }
    }

    /* 注意：原补丁在这里还会调 ksu_supercall_reboot_handler()，那是旧版 KernelSU 的
     * 符号。Nova 把 KSU_INSTALL_MAGIC2 的信令放在 supercall/supercall.c 里处理，
     * 这里只负责 SUSFS 那一路，其它 magic 一律交回 reboot 主流程。 */
    return -EINVAL;
}
"""


def die(msg):
    print("::error::" + msg)
    sys.exit(1)


def read(p):
    with io.open(p, encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(p, s):
    with io.open(p, "w", encoding="utf-8", newline="\n", errors="surrogateescape") as f:
        f.write(s)


def insert_before_last_endmenu(path):
    s = read(path)
    if "config KSU_SUSFS\n" in s:
        print("  [skip] Kconfig 已有 KSU_SUSFS")
        return
    idx = s.rfind("\nendmenu")
    if idx < 0:
        die("Kconfig 里找不到 endmenu: " + path)
    s = s[:idx] + "\n" + SUSFS_KCONFIG + s[idx:]
    write(path, s)
    print("  [ok]   Kconfig += SUSFS 菜单")


def patch_init_c(path):
    s = read(path)
    if "susfs_init()" in s:
        print("  [skip] init.c 已调用 susfs_init()")
        return
    anchor = "#include <linux/moduleparam.h>"
    if anchor not in s:
        die("init.c 找不到 include 锚点: " + path)
    s = s.replace(anchor, anchor + "\n#include <linux/susfs.h>", 1)

    fn = s.find("int __init kernelsu_init(void)")
    if fn < 0:
        die("init.c 找不到 kernelsu_init()")
    pi = s.find("pr_info(", fn)
    if pi < 0:
        die("init.c 的 kernelsu_init() 里找不到 pr_info(")
    eol = s.find("\n", pi)
    call = "\n#ifdef CONFIG_KSU_SUSFS\n    susfs_init();\n#endif"
    s = s[:eol] + call + s[eol:]
    write(path, s)
    print("  [ok]   init.c += susfs_init()")


def patch_dispatch_c(path):
    s = read(path)
    if "ksu_handle_sys_reboot" in s:
        print("  [skip] dispatch.c 已有 ksu_handle_sys_reboot")
        return
    anchor = "#include <linux/thread_info.h>"
    if anchor not in s:
        die("dispatch.c 找不到 include 锚点")
    s = s.replace(anchor, anchor + "\n#include <linux/susfs.h>", 1)
    if not s.endswith("\n"):
        s += "\n"
    s += "\n/* --- SUSFS: ksud 的 susfs 命令经由 reboot(2) 进入这里 --- */\n" + SUSFS_DISPATCH
    write(path, s)
    print("  [ok]   dispatch.c += ksu_handle_sys_reboot()")


def main():
    if len(sys.argv) < 2:
        die("用法: nova_susfs_port.py <KernelSU 仓库根目录>")
    root = sys.argv[1]
    k = os.path.join(root, "kernel")
    if not os.path.isdir(k):
        die("不是 KernelSU 仓库根目录（缺 kernel/）: " + root)

    insert_before_last_endmenu(os.path.join(k, "Kconfig"))
    # init.c 路径兼容两分支：main = core/init.c；builtin = ksu_main.c（已自带 susfs_init）
    init_c = os.path.join(k, "core", "init.c")
    if not os.path.exists(init_c):
        km = os.path.join(k, "ksu_main.c")
        if os.path.exists(km):
            m = read(km)
            if "susfs_init()" in m:
                print("  [skip] builtin ksu_main.c 已调用 susfs_init()")
            else:
                die("builtin ksu_main.c 缺少 susfs_init() 调用")
        else:
            die("找不到 init.c 或 ksu_main.c: " + k)
    else:
        patch_init_c(init_c)
    patch_dispatch_c(os.path.join(k, "supercall", "dispatch.c"))

    kv = read(os.path.join(k, "Kconfig"))
    ic = read(os.path.join(k, "ksu_main.c")) if not os.path.exists(init_c) else read(init_c)
    dc = read(os.path.join(k, "supercall", "dispatch.c"))
    checks = [
        ("Kconfig:config KSU_SUSFS", "config KSU_SUSFS\n" in kv),
        ("Kconfig:KSU_SUSFS_SUS_MAP", "config KSU_SUSFS_SUS_MAP" in kv),
        ("init.c:susfs_init()", "susfs_init();" in ic),
        ("init.c:#include susfs.h", "#include <linux/susfs.h>" in ic),
        ("dispatch.c:ksu_handle_sys_reboot", "int ksu_handle_sys_reboot(" in dc),
        ("dispatch.c:CMD_SUSFS_", "CMD_SUSFS_" in dc),
    ]
    bad = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  " + ("PASS" if ok else "FAIL") + "  " + n)
    if bad:
        die("SUSFS 移植校验失败: " + ", ".join(bad))
    print("SUSFS 移植完成（Nova 架构保持原样）")


if __name__ == "__main__":
    main()
