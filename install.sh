#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

plugin_name=xcy_safe
install_path=/www/server/panel/plugin/${plugin_name}
nginx_vhost_path=/www/server/panel/vhost/nginx
nginx_bin=/www/server/nginx/sbin/nginx

Install()
{
    echo '正在安装 JS挑战防火墙...'
    mkdir -p "${install_path}/rules"
    mkdir -p "${install_path}/access_logs"
    mkdir -p "${install_path}/static/css"
    mkdir -p "${install_path}/challenges"

    if [ ! -f "${install_path}/config.json" ]; then
        printf '{\n  "sites": {}\n}\n' > "${install_path}/config.json"
    fi

    if [ ! -f "${install_path}/logs.json" ]; then
        printf '[]\n' > "${install_path}/logs.json"
    fi

    chmod 600 "${install_path}/config.json" "${install_path}/logs.json" 2>/dev/null
    chmod 750 "${install_path}/access_logs" 2>/dev/null
    echo '================================================'
    echo 'JS挑战防火墙 v1.2 安装完成'
}

CleanNginxIncludes()
{
    if [ -d "${nginx_vhost_path}" ]; then
        find "${nginx_vhost_path}" -type f -name '*.conf' -exec perl -0pi -e 's/\n?\s*# BT-JS-CHALLENGE-START\n.*?# BT-JS-CHALLENGE-END\n?/\n/sg' {} \;
        find "${nginx_vhost_path}" -type f -name '*.conf' -exec perl -0pi -e 's/\n?\s*# BT-JS-CHALLENGE-LOCATION-START\n.*?# BT-JS-CHALLENGE-LOCATION-END\n?/\n/sg' {} \;
    fi
}

ReloadNginx()
{
    if [ -x "${nginx_bin}" ]; then
        "${nginx_bin}" -t >/dev/null 2>&1
        if [ "$?" -eq 0 ] && [ -x /etc/init.d/nginx ]; then
            /etc/init.d/nginx reload >/dev/null 2>&1
        fi
    fi
}

Uninstall()
{
    echo '正在卸载 JS挑战防火墙...'
    CleanNginxIncludes
    ReloadNginx
    rm -rf "${install_path}"
    echo 'JS挑战防火墙已卸载'
}

if [ "${1}" == 'install' ]; then
    Install
elif [ "${1}" == 'uninstall' ]; then
    Uninstall
else
    echo 'Error!'
fi
