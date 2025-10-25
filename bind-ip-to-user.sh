#!/usr/bin/env bash
# =========================================================
# bind-ip-manager-v5.sh — Debian 12 多IP绑定管理工具 (Vultr优化)
# 支持编号删除 / IPv4-only / SNAT自动修复 / 无 systemd 报错
# =========================================================
set -euo pipefail

# ---------- 工具 ----------
echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; }

require_root(){ [ "$(id -u)" -eq 0 ] || { echoerr "请以 root 运行"; exit 1; }; }
main_iface(){ ip route | awk '/default/ {print $5; exit}'; }
get_gw(){ ip route show default 0.0.0.0/0 | awk '/default/ {print $3; exit}'; }

fix_old_units(){
  for f in /etc/systemd/system/bind-u*-ip.service; do
    [ -f "$f" ] || continue
    sed -i '/Environment=/d' "$f" 2>/dev/null || true
  done
  systemctl daemon-reload
}

# ---------- 查看绑定 ----------
list_bindings(){
  mapfile -t BINDINGS < <(grep -l "Bind IP" /etc/systemd/system/bind-u*-ip.service 2>/dev/null || true)
}

show_bindings(){
  list_bindings
  echo
  if [ "${#BINDINGS[@]}" -eq 0 ]; then
    echowarn "暂无绑定。"
    return 1
  fi
  echoinfo "当前绑定："
  i=1
  for s in "${BINDINGS[@]}"; do
    ip=$(grep -oP 'SNAT --to-source \K[0-9.]+' "$s" || grep -oP 'src \K[0-9.]+' "$s" || echo "?")
    uid=$(grep -oP 'uid-owner \K[0-9]+' "$s" | head -n1)
    user=$(getent passwd "$uid" | cut -d: -f1 2>/dev/null || echo "未知")
    echo " [$i] 用户: $user (UID=$uid) → $ip"
    ((i++))
  done
  return 0
}

# ---------- 删除绑定（编号） ----------
delete_binding(){
  show_bindings || return
  echo
  read -rp "输入要删除的编号: " num
  if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#BINDINGS[@]}" ]; then
    echowarn "无效编号"; return
  fi
  svc="${BINDINGS[$((num-1))]}"
  uid=$(grep -oP 'uid-owner \K[0-9]+' "$svc" | head -n1)
  user=$(getent passwd "$uid" | cut -d: -f1 2>/dev/null || echo "未知")
  echoinfo "正在删除：$user (UID=$uid)"
  systemctl stop "bind-u${uid}-ip.service" 2>/dev/null || true
  systemctl disable "bind-u${uid}-ip.service" 2>/dev/null || true
  rm -f "$svc"
  iptables -t mangle -S OUTPUT | grep -- "--uid-owner $uid" | while read -r r; do iptables -t mangle ${r/-A/-D} || true; done
  iptables -t nat -S POSTROUTING | grep -- "--mark $((uid+1000))" | while read -r r; do iptables -t nat ${r/-A/-D} || true; done
  ip rule show | grep "u${uid}_tbl" | awk '{print $1}' | while read -r p; do ip rule del pref "$p" || true; done
  sed -i "/u${uid}_tbl/d" /etc/iproute2/rt_tables || true
  ip route flush table "u${uid}_tbl" 2>/dev/null || true
  echoinfo "✅ 已删除绑定：$user"
}

# ---------- 添加绑定 ----------
add_binding(){
  IFACE=$(main_iface)
  GW=$(get_gw)
  echoinfo "检测到主接口：$IFACE"
  echoinfo "检测到默认网关：$GW"

  mapfile -t IPS < <(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}')
  echo; echoinfo "可选 IP："
  i=1; for ip in "${IPS[@]}"; do echo " [$i] $ip"; ((i++)); done
  read -rp "选择编号: " c
  SEL_IP="${IPS[$((c-1))]%%/*}"
  read -rp "输入用户名: " U
  id "$U" &>/dev/null || { useradd -m -s /bin/bash "$U"; echoinfo "创建用户 $U"; }
  UIDNUM=$(id -u "$U"); TABLE="u${UIDNUM}_tbl"; MARK=$((UIDNUM+1000))
  grep -q "$TABLE" /etc/iproute2/rt_tables || echo "$((100+UIDNUM%900)) $TABLE" >> /etc/iproute2/rt_tables

  ip route flush table "$TABLE" 2>/dev/null || true
  ip route add default via "$GW" dev "$IFACE" src "$SEL_IP" table "$TABLE"
  ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
  ip rule add fwmark "$MARK" table "$TABLE" pref 500
  iptables -t mangle -A OUTPUT -m owner --uid-owner "$UIDNUM" -j MARK --set-xmark "$MARK"/0xffffffff

  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "")
  if [[ "$out" != "$SEL_IP" ]]; then
    echowarn "启用 SNAT..."
    iptables -t nat -A POSTROUTING -m mark --mark "$MARK" -j SNAT --to-source "$SEL_IP"
  fi
  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "")
  [[ "$out" == "$SEL_IP" ]] && echoinfo "✅ 成功绑定 $U 到 $SEL_IP" || echowarn "❌ 出口仍为 $out"

  SRV="/etc/systemd/system/bind-u${UIDNUM}-ip.service"
  cat >"$SRV"<<EOF
[Unit]
Description=Bind IP $SEL_IP to user $U
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c '/usr/sbin/ip route flush table $TABLE 2>/dev/null || true; /usr/sbin/ip route add default via $GW dev $IFACE src $SEL_IP table $TABLE; /usr/sbin/ip rule add fwmark $MARK table $TABLE pref 500 2>/dev/null || true; /usr/sbin/iptables -t mangle -A OUTPUT -m owner --uid-owner $UIDNUM -j MARK --set-xmark $MARK/0xffffffff; /usr/sbin/iptables -t nat -A POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP || true'
ExecStop=/usr/bin/bash -c '/usr/sbin/iptables -t mangle -D OUTPUT -m owner --uid-owner $UIDNUM -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true; /usr/sbin/iptables -t nat -D POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP 2>/dev/null || true; /usr/sbin/ip rule del fwmark $MARK table $TABLE 2>/dev/null || true; /usr/sbin/ip route flush table $TABLE 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "bind-u${UIDNUM}-ip.service"
}

# ---------- 菜单 ----------
menu(){
  clear
  echo "==============================="
  echo "  多IP绑定管理工具 (Debian12)"
  echo "==============================="
  echo "  [1] 查看当前绑定"
  echo "  [2] 删除绑定 (编号选择)"
  echo "  [3] 添加新绑定"
  echo "  [4] 退出"
  echo "-------------------------------"
  read -rp "请选择操作: " opt
  case "$opt" in
    1) show_bindings ;;
    2) delete_binding ;;
    3) add_binding ;;
    4) echoinfo "已退出"; exit 0 ;;
    *) echowarn "无效输入" ;;
  esac
  echo; read -rp "按回车返回菜单..." _
  menu
}

# ---------- 主流程 ----------
require_root
fix_old_units
menu
