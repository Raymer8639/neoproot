sed -i 's|https\?://[^/]*/termux|https://mirrors.tuna.tsinghua.edu.cn/termux|g' $PREFIX/etc/apt/sources.list
apt update
apt install debootstrap tar openssl curl -y
debootstrap --variant=minbase bookworm debian-bookworm https://mirrors.tuna.tsinghua.edu.cn/debian
script_content='#!/bin/bash
unset LD_PRELOAD
if [ -d "bind" ] && [ -n "$(ls -A bind 2>/dev/null)" ]; then
for dir in bind/*/; do
target="/$(basename "$dir")"
args="$args -b $dir:$target"
done
fi
command="../src/proot-scicat --link2symlink -0 -H -r debian-bookworm -b /dev -b /proc $args -w /root /usr/bin/env -i HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin:/usr/games:/usr/local/games TERM=$TERM LANG=zh_CN.UTF-8 SHELL=/bin/bash XDG_SESSION_TYPE=tty /usr/bin/bash -l"
exec $command ${@:2}
'
echo "$script_content" > start
chmod +x start
./start debian-bookworm