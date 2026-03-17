#!/usr/bin/env bash
# package.sh — 将编译好的二进制 + 资源文件打包成发行包
# 用法: cd dist && ../scripts/package.sh <version>
set -euo pipefail

VERSION="${1:?用法: package.sh <version>}"
PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="lobster-guard"

# 需要打包进去的资源文件 (相对于项目根目录)
ASSETS=(
    "README.md"
    "README_EN.md"
    "LICENSE"
    "nuclei-templates"
    "rules"
)

package_one() {
    local os="$1" arch="$2" ext="$3"
    local bin="${BINARY}-${os}-${arch}${ext}"
    local pkg_name="${BINARY}-v${VERSION}-${os}-${arch}"
    local staging="${pkg_name}"

    if [[ ! -f "$bin" ]]; then
        echo "  [!] 跳过 ${bin} (未找到)"
        return
    fi

    echo "  [*] 打包 ${pkg_name} ..."

    # 创建临时目录
    rm -rf "$staging"
    mkdir -p "$staging"

    # 复制二进制 (重命名为统一名称)
    if [[ "$os" == "windows" ]]; then
        cp "$bin" "${staging}/${BINARY}.exe"
    else
        cp "$bin" "${staging}/${BINARY}"
        chmod +x "${staging}/${BINARY}"
    fi

    # 复制资源文件
    for asset in "${ASSETS[@]}"; do
        if [[ -e "${PROJ_ROOT}/${asset}" ]]; then
            cp -r "${PROJ_ROOT}/${asset}" "${staging}/"
        fi
    done

    # 打包
    if [[ "$os" == "windows" ]]; then
        # Windows 用 zip
        if command -v zip &>/dev/null; then
            zip -rq "${pkg_name}.zip" "$staging"
        elif command -v 7z &>/dev/null; then
            7z a -tzip -bso0 "${pkg_name}.zip" "$staging"
        elif command -v powershell &>/dev/null; then
            local abs_staging abs_zip
            abs_staging="$(cd "$staging" && pwd -W 2>/dev/null || pwd)"
            abs_zip="$(pwd -W 2>/dev/null || pwd)/${pkg_name}.zip"
            powershell -NoProfile -Command "Compress-Archive -Path '${abs_staging}' -DestinationPath '${abs_zip}' -Force"
        else
            echo "  [!] 未找到 zip/7z/powershell, 跳过 Windows 打包"
            rm -rf "$staging"
            return
        fi
    else
        # Linux/macOS 用 tar.gz
        tar czf "${pkg_name}.tar.gz" "$staging"
    fi

    # 清理临时目录
    rm -rf "$staging"
    echo "  [+] ${pkg_name} 完成"
}

echo "=== LobsterGuard v${VERSION} 发行包打包 ==="
echo ""

package_one "windows" "amd64" ".exe"
package_one "linux"   "amd64" ""
package_one "linux"   "arm64" ""
package_one "darwin"  "amd64" ""
package_one "darwin"  "arm64" ""

echo ""
echo "=== 打包完成 ==="
ls -lh *.zip *.tar.gz 2>/dev/null || true
