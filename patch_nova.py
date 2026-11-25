#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 Build_Lenovo_sm8750.yml 从 BakaSU 切换到 SukiSU-Nova，并补齐：
  - SukiSU-Nova 内核接入（GitHub 官方源，不走自建 git）
  - CONFIG_KPM / KALLSYMS_ALL
  - KernelPatch(kpimg) 打入 Image，让 KPM 真正可用
  - kairos(MEMX) 只读驱动
  - selinux_hide / mount_hide / kernel_umount（Nova 内建，等价 NoMount）
"""
import io
import sys

P = '.github/workflows/Build_Lenovo_sm8750.yml'
s = io.open(P, encoding='utf-8').read()
orig = s

# ---------------------------------------------------------------- 1. 输入项
anchor_inputs = """      enable_susfs:
        description: "启用SUSFS"
        required: true
        default: true
        type: boolean
"""
new_inputs = anchor_inputs + """
      enable_kpm:
        description: "启用 KPM（构建时会把 KernelPatch kpimg 打入 Image）"
        required: true
        default: true
        type: boolean

      enable_kairos:
        description: "启用 kairos(MEMX) 只读内核读写驱动"
        required: true
        default: true
        type: boolean

      nova_ref:
        description: "SukiSU-Nova 分支/标签/提交（留空=main）"
        required: false
        default: ''
"""
assert anchor_inputs in s
s = s.replace(anchor_inputs, new_inputs, 1)

# ---------------------------------------------------------------- 2. env
anchor_env = """      ENABLE_SUSFS: ${{ github.event.inputs.enable_susfs }}
      ENABLE_SIGNED: ${{ github.event.inputs.enable_signed }}
"""
new_env = """      ENABLE_SUSFS: ${{ github.event.inputs.enable_susfs }}
      ENABLE_KPM: ${{ github.event.inputs.enable_kpm }}
      ENABLE_KAIROS: ${{ github.event.inputs.enable_kairos }}
      NOVA_REF: ${{ github.event.inputs.nova_ref }}
      ENABLE_SIGNED: ${{ github.event.inputs.enable_signed }}
"""
assert anchor_env in s
s = s.replace(anchor_env, new_env, 1)

# ---------------------------------------------------------------- 3. root 方案
old_ksu = """      - name: ⚙️ Set BakaSU (设置BakaSU)
        run: |
          cd kernel_workspace
          echo "正在配置BakaSU..."
          curl -LSs "https://raw.githubusercontent.com/Baka-SU/BakaSU/refs/heads/main/kernel/setup.sh" | bash -s main
          cd ./KernelSU 
          KSU_VERSION=$(expr $(git rev-list --count origin/main 2>/dev/null) + 30700 2>/dev/null || echo 114514)
          echo "KSUVER=$KSU_VERSION" >> $GITHUB_ENV
          echo "ksuver=$KSU_VERSION" >> $GITHUB_OUTPUT
"""

new_ksu = """      - name: ⚙️ Set SukiSU-Nova (设置 SukiSU-Nova)
        run: |
          set -euo pipefail
          cd kernel_workspace
          echo "正在配置 SukiSU-Nova ..."

          # 注意：上游 kernel/setup.sh 会从自建 git (git.zako.shirkneko.top) 拉源码，
          # CI 里改成 GitHub 官方仓库，避免依赖第三方源；挂载方式与 setup.sh 完全一致。
          rm -rf KernelSU
          git clone https://github.com/SukiSU-Nova/SukiSU-Nova.git KernelSU
          cd KernelSU
          if [ -n "${NOVA_REF:-}" ]; then
            echo "==> 切到指定 ref: $NOVA_REF"
            git checkout "$NOVA_REF"
          fi
          NOVA_SHA=$(git rev-parse --short=8 HEAD)
          KSU_VERSION=$(expr $(git rev-list --count HEAD 2>/dev/null || echo 0) + 30000)
          echo "NOVA_SHA=$NOVA_SHA" >> $GITHUB_ENV
          echo "KSUVER=$KSU_VERSION" >> $GITHUB_ENV
          echo "ksuver=$KSU_VERSION" >> $GITHUB_OUTPUT
          echo "==> Nova commit: $NOVA_SHA  version: $KSU_VERSION"
          cd ..

          # 挂到内核树（等价 kernel/setup.sh 的三步）
          ln -sfn "$(realpath --relative-to=./common/drivers ./KernelSU/kernel)" ./common/drivers/kernelsu
          grep -q 'obj-$(CONFIG_KSU) += kernelsu/' ./common/drivers/Makefile || \\
            printf '\\nobj-$(CONFIG_KSU) += kernelsu/\\n' >> ./common/drivers/Makefile
          grep -q 'drivers/kernelsu/Kconfig' ./common/drivers/Kconfig || \\
            sed -i '/^endmenu/i source "drivers/kernelsu/Kconfig"' ./common/drivers/Kconfig

          echo "== 挂载校验 =="
          ls -l ./common/drivers/kernelsu
          grep -n 'kernelsu' ./common/drivers/Makefile ./common/drivers/Kconfig

          echo "== Nova 提供的能力（源码实证）=="
          echo "-- feature/  :"; ls ./KernelSU/kernel/feature
          echo "-- extension/:"; ls ./KernelSU/kernel/extension
          echo "   => selinux_hide / mount_hide / kernel_umount / umount_paths 内建（等价 NoMount）"
          echo "   => cpu_spoof / uts_spoof / avc_spoof 内建（内核层伪装）"
          echo "   => extension/kpm 内建（Kernel Patch Module）"
"""

assert old_ksu in s
s = s.replace(old_ksu, new_ksu, 1)

# ---------------------------------------------------------------- 4. KSU defconfig
old_cfg = """          # ==================== KSU 配置 ====================
          echo "CONFIG_KSU=y" >> "$DEFCONFIG"

          echo 'CONFIG_KSU_FULL_NAME_FORMAT="%TAG_NAME%-%COMMIT_SHA%-Re-TG@qdykernel"' >> "$DEFCONFIG"
"""
new_cfg = """          # ==================== KSU 配置（SukiSU-Nova）====================
          echo "CONFIG_KSU=y" >> "$DEFCONFIG"
          echo "CONFIG_KSU_MANUAL_SU=y" >> "$DEFCONFIG"

          # ---- KPM（Kernel Patch Module）----
          if [ "${ENABLE_KPM}" == 'true' ]; then
            echo "CONFIG_KPM=y" >> "$DEFCONFIG"
            echo "CONFIG_KALLSYMS=y" >> "$DEFCONFIG"
            echo "CONFIG_KALLSYMS_ALL=y" >> "$DEFCONFIG"
            echo "✅ 已启用 CONFIG_KPM / KALLSYMS_ALL"
          else
            echo "未启用 KPM，跳过"
          fi
"""
assert old_cfg in s
s = s.replace(old_cfg, new_cfg, 1)

# ---------------------------------------------------------------- 5. kairos 步骤加固
old_kairos = """      - name: 🧩 Integrate kairos (MEMX) read-only driver
        run: |
          set -e
          cd kernel_workspace
          echo "==> 拉取 kairos 驱动源码"
          git clone --depth=1 -b kairos-ko-test https://github.com/Xran66/GKI_BakaSU_SUSFS.git kairos_src
          echo "==> 拷入内核树"
          cp -r kairos_src/kairos/drivers/kairos ./common/drivers/
          grep -q 'drivers/kairos/Kconfig' ./common/drivers/Kconfig || echo 'source "drivers/kairos/Kconfig"' >> ./common/drivers/Kconfig
          grep -q 'kairos/' ./common/drivers/Makefile || echo 'obj-$(CONFIG_MEMX) += kairos/' >> ./common/drivers/Makefile
          echo "==> 注入源码级调用点 (net/socket.c, kernel/reboot.c)"
          python3 kairos_src/kairos/patches/inject_hooks.py ./common
          echo "==> 写入 MEMX 配置"
          DEF=./common/arch/arm64/configs/gki_defconfig
          for c in CONFIG_MEMX=y CONFIG_MEMX_GYRO_HOOK=y; do
            grep -q "^${c}" $DEF || echo "$c" >> $DEF
          done
          grep -n "CONFIG_MEMX" $DEF
          echo "✅ kairos 集成完成"
"""

new_kairos = """      - name: 🧩 Integrate kairos (MEMX) read-only driver
        if: ${{ env.ENABLE_KAIROS == 'true' }}
        run: |
          set -euo pipefail
          cd kernel_workspace
          echo "==> 拉取 kairos 驱动源码"
          rm -rf kairos_src
          git clone --depth=1 -b kairos-ko-test https://github.com/Xran66/GKI_BakaSU_SUSFS.git kairos_src

          echo "==> 拷入内核树"
          rm -rf ./common/drivers/kairos
          cp -r kairos_src/kairos/drivers/kairos ./common/drivers/
          grep -q 'drivers/kairos/Kconfig' ./common/drivers/Kconfig || \\
            sed -i '/^endmenu/i source "drivers/kairos/Kconfig"' ./common/drivers/Kconfig
          grep -q 'kairos/' ./common/drivers/Makefile || \\
            printf '\\nobj-$(CONFIG_MEMX) += kairos/\\n' >> ./common/drivers/Makefile

          echo "==> 注入源码级调用点 (net/socket.c __sys_sendto, kernel/reboot.c)"
          python3 kairos_src/kairos/patches/inject_hooks.py ./common
          echo "--- 注入结果校验 ---"
          grep -n 'memx\\|MEMX' ./common/net/socket.c | head -5 || echo "!! net/socket.c 未命中"
          grep -n 'memx\\|MEMX' ./common/kernel/reboot.c | head -5 || echo "!! kernel/reboot.c 未命中"

          echo "==> 写入 MEMX 配置（只读，写入路径不编译）"
          DEF=./common/arch/arm64/configs/gki_defconfig
          for c in "CONFIG_MEMX=y" "CONFIG_MEMX_GYRO_HOOK=y" "CONFIG_MEMX_WRITE_ENABLE=0"; do
            grep -q "^${c%%=*}=y\\|^${c}" $DEF || echo "$c" >> $DEF
          done
          grep -n "CONFIG_MEMX" $DEF
          echo "✅ kairos 集成完成"
"""
assert old_kairos in s
s = s.replace(old_kairos, new_kairos, 1)

# ---------------------------------------------------------------- 6. KernelPatch 打 Image
anchor_build_end = """      - name: 🕒 Calculate build time (计算构建时间)"""

kp_step = """      - name: 🩹 Patch Image with KernelPatch (写入 kpimg，启用 KPM)
        if: ${{ env.ENABLE_KPM == 'true' }}
        run: |
          set -euo pipefail
          cd kernel_workspace/common/out/arch/arm64/boot
          ls -lh Image

          # SukiSU_patch/kpm/patch_linux 是官方 x86_64 工具：读当前目录的 Image，
          # 解密内嵌 kptools + kpimg，把 kpimg 附加到 Image 尾部并改写启动入口，
          # 产物固定为 oImage。
          BASE="https://raw.githubusercontent.com/SukiSU-Nova/SukiSU_patch/main/kpm"
          curl -LSs "$BASE/patch_linux" -o patch_linux
          chmod +x patch_linux
          ./patch_linux

          if [ ! -f oImage ]; then
            echo "::error::KernelPatch 未生成 oImage"
            exit 1
          fi
          ls -lh Image oImage
          # 大小应约为原 Image + kpimg(≈288KB)
          cp -f oImage Image
          echo "✅ Image 已注入 kpimg（KPM 可用）"

""" + anchor_build_end

assert anchor_build_end in s
s = s.replace(anchor_build_end, kp_step, 1)

# ---------------------------------------------------------------- 7. 产物名
s = s.replace(
    "name: Boot_${{ env.KSUVER }}_${{ env.KERNEL_VERSION }}_BakaSU_AOSP_Signed",
    "name: Boot_${{ env.KSUVER }}_${{ env.KERNEL_VERSION }}_SukiSU-Nova_AOSP_Signed"
)

io.open(P, 'w', encoding='utf-8', newline='\n').write(s)
print("patched OK, lines:", len(s.splitlines()))

# 简单语法自检
import re
for bad in ('BakaSU', 'CONFIG_KSU_FULL_NAME_FORMAT'):
    hits = [i + 1 for i, l in enumerate(s.splitlines()) if bad in l]
    print(f"  remaining '{bad}': {hits}")
