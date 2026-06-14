#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔 Linux 面板第三方插件：星辰云防火墙
# +-------------------------------------------------------------------

import codecs
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid

try:
    import base64
except Exception:
    base64 = None


if os.path.isdir('/www/server/panel'):
    os.chdir('/www/server/panel')
sys.path.append('class/')

try:
    import public
except Exception:
    public = None

try:
    text_type = unicode
except NameError:
    text_type = str


class xcy_safe_main:
    __plugin_path = '/www/server/panel/plugin/xcy_safe/'
    __config_file = os.path.join(__plugin_path, 'config.json')
    __log_file = os.path.join(__plugin_path, 'logs.json')
    __rule_dir = os.path.join(__plugin_path, 'rules')
    __access_log_dir = os.path.join(__plugin_path, 'access_logs')
    __challenge_template_dir = os.path.join(__plugin_path, 'challenges')
    __nginx_conf_dir = '/www/server/panel/vhost/nginx'
    __nginx_bin = '/www/server/nginx/sbin/nginx'
    __marker_start = '# BT-JS-CHALLENGE-START'
    __marker_end = '# BT-JS-CHALLENGE-END'
    __location_marker_start = '# BT-JS-CHALLENGE-LOCATION-START'
    __location_marker_end = '# BT-JS-CHALLENGE-LOCATION-END'
    __max_log_rows = 1000
    __challenge_pending_grace = 300
    __challenge_pass_window = 1800
    __runtime_prefix = 'xcy_idc_challenge_'
    __config = None
    __config_cache_time = 0
    __config_cache_ttl = 10
    __challenge_log_max_age_days = 30
    __challenge_log_cleanup_check_interval = 3600
    __last_cleanup_check = 0

    __challenge_types = [
        {'value': 'cookie_delay', 'title': u'Cookie延时挑战'},
        {'value': 'fingerprint', 'title': u'浏览器指纹挑战'},
        {'value': 'captcha', 'title': u'验证码挑战'},
        {'value': 'arithmetic', 'title': u'算术挑战'},
        {'value': 'pow_hash', 'title': u'PoW/Hash计算挑战'}
    ]

    __legacy_challenge_title = u'安全验证'
    __legacy_challenge_text = u'正在进行浏览器安全验证，请稍候...'

    __default_site_setting = {
        'enabled': False,
        'challenge_type': 'cookie_delay',
        'cookie_ttl': 3600,
        'challenge_delay': 600,
        'pow_difficulty': 3,
        'challenge_title': u'星辰云IDC安全验证',
        'challenge_text': u'星辰云IDC正在检查你的浏览器...',
        'exclude_ext': 'css,js,png,jpg,jpeg,gif,svg,ico,webp,woff,woff2,ttf,map',
        'ip_whitelist': []
    }

    def __init__(self):
        self.__ensure_storage()

    def index(self, args):
        return self.get_sites(args)

    def get_sites(self, args):
        if public is None:
            return self.__fail(u'未检测到宝塔 public 模块，请在宝塔面板插件环境中运行')

        site_list = self.__list_sites()
        if site_list is None:
            return self.__fail(u'读取网站列表失败')

        result = []
        for site in site_list:
            site_name = self.__to_text(site.get('name', ''))
            setting = self.__get_site_setting(site_name)
            conf_path = self.__site_conf_path(site_name)
            nginx_active = self.__nginx_include_exists(site_name)
            setting['enabled'] = bool(setting.get('enabled'))
            item = {
                'id': site.get('id', 0),
                'name': site_name,
                'path': self.__to_text(site.get('path', '')),
                'status': site.get('status', ''),
                'ps': self.__to_text(site.get('ps', '')),
                'addtime': self.__to_text(site.get('addtime', '')),
                'supported': os.path.exists(conf_path),
                'conf_path': conf_path,
                'active': nginx_active,
                'effective_enabled': bool(setting.get('enabled')) and nginx_active,
                'need_sync': bool(setting.get('enabled')) and not nginx_active,
                'setting': setting
            }
            result.append(item)

        return {
            'status': True,
            'sites': result,
            'challenge_types': self.__challenge_types,
            'default_setting': self.__default_site_setting
        }

    def save_site(self, args):
        if public is None:
            return self.__fail(u'未检测到宝塔 public 模块，请在宝塔面板插件环境中运行')

        site_name = self.__to_text(self.__get_arg(args, 'site_name', '')).strip()
        if not site_name:
            return self.__fail(u'缺少站点名称')

        site = self.__get_site_by_name(site_name)
        if not site:
            return self.__fail(u'站点不存在：' + site_name)

        conf_path = self.__site_conf_path(site_name)
        if not os.path.exists(conf_path):
            return self.__fail(u'未找到 Nginx 站点配置：' + conf_path)

        setting = self.__normalize_setting(args, self.__get_site_setting(site_name))

        if setting.get('enabled'):
            result = self.__enable_site(site_name, setting)
        else:
            result = self.__disable_site(site_name)

        if result.get('status'):
            config = self.__get_config()
            old_site_setting = config.setdefault('sites', {}).get(site_name)
            save_setting = dict(setting)
            if 'cookie_name' in save_setting:
                del save_setting['cookie_name']
            config.setdefault('sites', {})[site_name] = save_setting
            if not self.__write_config(config):
                if old_site_setting is not None:
                    config['sites'][site_name] = old_site_setting
                else:
                    config['sites'].pop(site_name, None)
                self.__config = config
                message = u'写入插件配置失败，请检查 config.json 权限：' + self.__config_file
                self.__append_log(u'失败', site_name, message)
                return self.__fail(message)
            action = u'启用' if setting.get('enabled') else u'关闭'
            message = action + u'站点 JS 挑战：' + site_name
            if result.get('warning'):
                message += u'；' + result.get('warning')
            self.__append_log(action, site_name, message)
            self.__write_panel_log(message)
        else:
            self.__append_log(u'失败', site_name, result.get('msg', u'保存站点设置失败'))

        return result

    def get_logs(self, args):
        page = self.__safe_int(self.__get_arg(args, 'p', 1), 1, 1, 999999)
        rows = self.__safe_int(self.__get_arg(args, 'rows', 12), 12, 1, 100)
        callback = self.__to_text(self.__get_arg(args, 'callback', ''))
        logs = self.__read_logs()
        count = len(logs)
        start = (page - 1) * rows
        end = start + rows
        data = logs[start:end]

        if public is not None:
            page_data = public.get_page(count, page, rows, callback)
            page_html = page_data.get('page', '')
        else:
            page_html = ''

        return {'status': True, 'data': data, 'page': page_html, 'count': count}

    def clear_logs(self, args):
        self.__write_logs([])
        message = u'清理 JS 挑战防火墙插件日志'
        self.__write_panel_log(message)
        return {'status': True, 'msg': u'日志已清理'}

    def get_challenge_logs(self, args):
        self.__auto_cleanup_challenge_logs()
        page = self.__safe_int(self.__get_arg(args, 'p', 1), 1, 1, 999999)
        rows = self.__safe_int(self.__get_arg(args, 'rows', 15), 15, 1, 100)
        callback = self.__to_text(self.__get_arg(args, 'callback', ''))
        logs = self.__read_challenge_logs()
        count = len(logs)
        start = (page - 1) * rows
        end = start + rows
        data = logs[start:end]

        if public is not None:
            page_data = public.get_page(count, page, rows, callback)
            page_html = page_data.get('page', '')
        else:
            page_html = ''

        return {'status': True, 'data': data, 'page': page_html, 'count': count}

    def clear_challenge_logs(self, args):
        for filename in self.__challenge_log_files():
            try:
                self.__write_text(filename, '')
            except Exception:
                pass
        message = u'清理 JS 挑战访问日志'
        self.__write_panel_log(message)
        return {'status': True, 'msg': u'挑战日志已清理'}

    def batch_enable_sites(self, args):
        site_names = self.__parse_site_names(args)
        if not site_names:
            return self.__fail(u'请选择至少一个站点')
        results = []
        for site_name in site_names:
            site = self.__get_site_by_name(site_name)
            if not site:
                results.append({'site': site_name, 'status': False, 'msg': u'站点不存在'})
                continue
            conf_path = self.__site_conf_path(site_name)
            if not os.path.exists(conf_path):
                results.append({'site': site_name, 'status': False, 'msg': u'无Nginx配置'})
                continue
            setting = self.__get_site_setting(site_name)
            setting['enabled'] = True
            result = self.__enable_site(site_name, setting)
            results.append({'site': site_name, 'status': result.get('status', False), 'msg': result.get('msg', '')})
            if result.get('status'):
                config = self.__get_config()
                save_setting = dict(setting)
                if 'cookie_name' in save_setting:
                    del save_setting['cookie_name']
                config.setdefault('sites', {})[site_name] = save_setting
                self.__write_config(config)
                self.__append_log(u'批量启用', site_name, u'批量启用 JS 挑战')
        self.__reload_nginx()
        return {'status': True, 'results': results, 'msg': u'批量操作完成'}

    def batch_disable_sites(self, args):
        site_names = self.__parse_site_names(args)
        if not site_names:
            return self.__fail(u'请选择至少一个站点')
        results = []
        for site_name in site_names:
            result = self.__disable_site(site_name)
            results.append({'site': site_name, 'status': result.get('status', False), 'msg': result.get('msg', '')})
            if result.get('status'):
                config = self.__get_config()
                config.setdefault('sites', {}).pop(site_name, None)
                self.__write_config(config)
                self.__append_log(u'批量关闭', site_name, u'批量关闭 JS 挑战')
        self.__reload_nginx()
        return {'status': True, 'results': results, 'msg': u'批量操作完成'}

    def export_config(self, args):
        config = self.__get_config()
        export_data = {
            'version': '1.2',
            'export_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'sites': config.get('sites', {})
        }
        return {'status': True, 'data': json.dumps(export_data, ensure_ascii=False, indent=2)}

    def import_config(self, args):
        raw = self.__get_arg(args, 'data', '')
        if not raw:
            return self.__fail(u'未提供配置数据')
        try:
            import_data = json.loads(self.__to_text(raw))
        except Exception:
            return self.__fail(u'配置数据格式错误，无法解析 JSON')
        if not isinstance(import_data, dict) or 'sites' not in import_data:
            return self.__fail(u'配置数据缺少 sites 字段')
        config = self.__get_config()
        imported = import_data.get('sites', {})
        if not isinstance(imported, dict):
            return self.__fail(u'配置数据 sites 格式错误')
        merged_count = 0
        for site_name, site_setting in imported.items():
            if not isinstance(site_setting, dict):
                continue
            existing = config.setdefault('sites', {}).get(site_name, {})
            merged = dict(self.__default_site_setting)
            merged.update(site_setting)
            merged['token'] = existing.get('token', merged.get('token', uuid.uuid4().hex))
            config['sites'][site_name] = merged
            merged_count += 1
        if not self.__write_config(config):
            return self.__fail(u'写入配置失败')
        message = u'导入配置，共合并 ' + self.__to_text(str(merged_count)) + u' 个站点'
        self.__append_log(u'导入', '-', message)
        self.__write_panel_log(message)
        return {'status': True, 'msg': u'成功导入 ' + self.__to_text(str(merged_count)) + u' 个站点配置'}

    def __parse_site_names(self, args):
        raw = self.__get_arg(args, 'site_names', '')
        if isinstance(raw, list):
            return [self.__to_text(n).strip() for n in raw if self.__to_text(n).strip()]
        names = []
        for part in self.__to_text(raw).split(','):
            name = part.strip()
            if name:
                names.append(name)
        return names

    def __auto_cleanup_challenge_logs(self):
        now = time.time()
        if now - self.__last_cleanup_check < self.__challenge_log_cleanup_check_interval:
            return
        self.__last_cleanup_check = now
        max_age_seconds = self.__challenge_log_max_age_days * 86400
        deleted = 0
        for filename in self.__challenge_log_files():
            try:
                if now - os.path.getmtime(filename) > max_age_seconds:
                    os.remove(filename)
                    deleted += 1
            except Exception:
                pass
        if deleted > 0:
            self.__write_panel_log(u'自动清理 ' + self.__to_text(str(deleted)) + u' 个过期挑战日志文件')

    def __enable_site(self, site_name, setting):
        conf_path = self.__site_conf_path(site_name)
        rule_path = self.__rule_path(site_name)
        guard_path = self.__guard_rule_path(site_name)
        original_conf = self.__read_text(conf_path)
        if original_conf is None:
            return self.__fail(u'读取 Nginx 站点配置失败：' + conf_path)

        rule_body = self.__build_nginx_rule(site_name, setting, guard_path)
        if not self.__write_text(rule_path, rule_body):
            return self.__fail(u'写入 JS 挑战规则失败：' + rule_path)
        if not self.__write_text(guard_path, self.__build_guard_rule(site_name)):
            return self.__fail(u'写入 JS 挑战拦截规则失败：' + guard_path)

        include_block = self.__build_include_block(rule_path)
        clean_conf = self.__remove_location_guard_block(original_conf)
        new_conf = self.__replace_include_block(clean_conf, include_block)
        if new_conf == clean_conf:
            new_conf = self.__insert_include_block(clean_conf, include_block)
        if new_conf is None:
            return self.__fail(u'未找到 server 配置块，无法插入 JS 挑战规则')
        guarded_conf = self.__insert_location_guard_block(new_conf, guard_path)
        if guarded_conf:
            new_conf = guarded_conf

        if not self.__write_text(conf_path, new_conf):
            return self.__fail(u'写入 Nginx 站点配置失败：' + conf_path)

        test_result = self.__test_nginx()
        if not test_result.get('status'):
            self.__write_text(conf_path, original_conf)
            return self.__fail(u'Nginx 配置检测失败，已回滚：' + test_result.get('msg', ''))

        reload_result = self.__reload_nginx()
        if not reload_result.get('status'):
            return {
                'status': True,
                'msg': u'JS 挑战已启用，但 Nginx 重载失败，请手动检查',
                'warning': reload_result.get('msg', '')
            }

        return {'status': True, 'msg': u'JS 挑战已启用'}

    def __disable_site(self, site_name):
        conf_path = self.__site_conf_path(site_name)
        if not os.path.exists(conf_path):
            return self.__fail(u'未找到 Nginx 站点配置：' + conf_path)

        original_conf = self.__read_text(conf_path)
        if original_conf is None:
            return self.__fail(u'读取 Nginx 站点配置失败：' + conf_path)

        new_conf = self.__remove_location_guard_block(self.__remove_include_block(original_conf))
        if new_conf != original_conf and not self.__write_text(conf_path, new_conf):
            return self.__fail(u'写入 Nginx 站点配置失败：' + conf_path)

        rule_path = self.__rule_path(site_name)
        if os.path.exists(rule_path):
            try:
                os.remove(rule_path)
            except Exception:
                return self.__fail(u'删除 JS 挑战规则失败：' + rule_path)
        guard_path = self.__guard_rule_path(site_name)
        if os.path.exists(guard_path):
            try:
                os.remove(guard_path)
            except Exception:
                return self.__fail(u'删除 JS 挑战拦截规则失败：' + guard_path)

        test_result = self.__test_nginx()
        if not test_result.get('status'):
            return {
                'status': True,
                'msg': u'JS 挑战已关闭，但当前 Nginx 配置检测失败，请检查其它站点配置',
                'warning': test_result.get('msg', '')
            }

        reload_result = self.__reload_nginx()
        if not reload_result.get('status'):
            return {
                'status': True,
                'msg': u'JS 挑战已关闭，但 Nginx 重载失败，请手动检查',
                'warning': reload_result.get('msg', '')
            }

        return {'status': True, 'msg': u'JS 挑战已关闭'}

    def __build_nginx_rule(self, site_name, setting, guard_path=None):
        var_suffix = self.__site_hash(site_name)[:12]
        variable_name = self.__runtime_prefix + var_suffix
        passed_variable_name = self.__runtime_prefix + 'passed_' + var_suffix
        access_log_variable_name = self.__runtime_prefix + 'access_' + var_suffix
        location_name = '@' + self.__runtime_prefix + var_suffix
        cookie_name = self.__cookie_name(site_name)
        token = self.__to_text(setting.get('token', ''))
        ttl = self.__safe_int(setting.get('cookie_ttl'), 3600, 60, 86400)
        delay = self.__safe_int(setting.get('challenge_delay'), 600, 0, 5000)
        ext_regex = self.__build_ext_regex(setting.get('exclude_ext', ''))
        cookie_pattern = self.__cookie_pass_pattern(site_name, setting, token)
        challenge_html = self.__build_challenge_html(site_name, setting, cookie_name, token, ttl, delay)
        challenge_type = self.__clean_challenge_type(setting.get('challenge_type'))
        challenge_log_path = self.__challenge_log_path(site_name, 'challenge')
        passed_log_path = self.__challenge_log_path(site_name, 'passed')
        body_variable_prefix = self.__runtime_prefix + 'body_' + var_suffix
        body_lines, body_expression = self.__build_nginx_body_lines(body_variable_prefix, challenge_html)

        lines = [
            u'# 本文件由宝塔 JS 挑战防火墙插件生成，请在插件页面修改设置。',
            'set ${0} 1;'.format(variable_name),
            'set ${0} 0;'.format(passed_variable_name),
            'set ${0} 0;'.format(access_log_variable_name),
        ]
        ip_whitelist = setting.get('ip_whitelist', [])
        if isinstance(ip_whitelist, list) and len(ip_whitelist) > 0:
            for ip_entry in ip_whitelist:
                ip_entry = self.__to_text(ip_entry).strip()
                if not ip_entry:
                    continue
                if '/' in ip_entry:
                    pattern = self.__cidr_to_nginx_pattern(ip_entry)
                    if pattern:
                        lines.append('if ($remote_addr ~ "{0}") {{ set ${1} 0; set ${2} 0; }}'.format(pattern, variable_name, access_log_variable_name))
                else:
                    lines.append('if ($remote_addr = "{0}") {{ set ${1} 0; set ${2} 0; }}'.format(ip_entry, variable_name, access_log_variable_name))
        lines.extend([
            'if ($request_method != GET) {',
            '    set ${0} 0;'.format(variable_name),
            '    set ${0} 0;'.format(access_log_variable_name),
            '}',
            'if ($http_cookie ~* "(^|;\\\\s*){0}={1}(;|$)") {{'.format(cookie_name, cookie_pattern),
            '    set ${0} 0;'.format(variable_name),
            '    set ${0} 1;'.format(passed_variable_name),
            '    set ${0} 1;'.format(access_log_variable_name),
            '}',
            'if ($request_uri ~* "^/(?:\\\\.well-known/acme-challenge/|favicon\\\\.ico)") {',
            '    set ${0} 0;'.format(variable_name),
            '    set ${0} 0;'.format(access_log_variable_name),
            '}'
        ])
        if ext_regex:
            lines.extend([
                'if ($uri ~* "\\\\.(?:{0})$") {{'.format(ext_regex),
                '    set ${0} 0;'.format(variable_name),
                '    set ${0} 0;'.format(access_log_variable_name),
                '}'
            ])
        lines.extend([
            'access_log {0} combined if=${1};'.format(passed_log_path, access_log_variable_name),
            'if (${0} = 1) {{ return 470; }}'.format(variable_name),
            'error_page 470 = {0};'.format(location_name),
            'location {0} {{'.format(location_name),
            '    access_log {0} combined;'.format(challenge_log_path),
            '    add_header Content-Type "text/html; charset=utf-8" always;',
            '    add_header Cache-Control "no-store, no-cache, must-revalidate" always;',
            '    add_header X-Robots-Tag "noindex, nofollow" always;',
            '    add_header X-BT-JS-Challenge "{0}" always;'.format(challenge_type),
        ])
        lines.extend(body_lines)
        lines.extend([
            '    return 200 "{0}";'.format(body_expression),
            '}',
            ''
        ])
        return u'\n'.join(lines)

    def __build_guard_rule(self, site_name):
        var_suffix = self.__site_hash(site_name)[:12]
        variable_name = self.__runtime_prefix + var_suffix
        return 'if (${0} = 1) {{ return 470; }}\n'.format(variable_name)

    def __read_challenge_template(self, name):
        filename = os.path.join(self.__challenge_template_dir, self.__to_text(name) + '.html')
        content = self.__read_text(filename)
        if not content:
            return None
        return content

    def __build_challenge_html(self, site_name, setting, cookie_name, token, ttl, delay):
        challenge_type = self.__clean_challenge_type(setting.get('challenge_type'))
        title = self.__to_text(setting.get('challenge_title') or self.__default_site_setting['challenge_title'])
        text = self.__to_text(setting.get('challenge_text') or self.__default_site_setting['challenge_text'])
        template = self.__read_challenge_template(challenge_type)
        if not template:
            html = (
                u''
                '<!doctype html><html><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>%s</title>'
                '<style>body{margin:0;font-family:Arial,"Microsoft YaHei",sans-serif;background:#f5f7fb;color:#1f2937;}'
                '.box{max-width:520px;margin:18vh auto 0;padding:32px;background:#fff;border:1px solid #e5e7eb;border-radius:8px;text-align:center;}'
                '.spinner{width:34px;height:34px;margin:0 auto 18px;border:3px solid #d1d5db;border-top-color:#2563eb;border-radius:50%%;animation:spin 1s linear infinite;}'
                '@keyframes spin{to{transform:rotate(360deg);}}h1{font-size:22px;margin:0 0 12px;}p{font-size:14px;line-height:1.7;margin:0;color:#4b5563;}'
                '.state{margin-top:14px;font-size:13px;color:#6b7280;}</style>'
                '</head><body><div class="box"><div class="spinner"></div><h1>%s</h1><p>%s</p><p class="state">验证中...</p></div></body></html>'
            ) % (self.__html_escape(title), self.__html_escape(title), self.__html_escape(text))
            return html

        replacements = {
            u'{title}': self.__html_escape(title),
            u'{text}': self.__html_escape(text),
            u'{cookie_name}': self.__to_text(cookie_name),
            u'{token}': self.__to_text(token),
            u'{ttl}': self.__to_text(str(ttl)),
            u'{delay}': self.__to_text(str(delay))
        }

        if challenge_type == 'captcha':
            code = self.__captcha_code(setting, token)
            image_src = self.__captcha_image_data_uri(code, self.__to_text(setting.get('token', '')))
            replacements[u'{captcha_code}'] = self.__to_text(code)
            replacements[u'{captcha_image}'] = self.__to_text(image_src)

        if challenge_type == 'arithmetic':
            math_data = self.__arithmetic_challenge(site_name, token)
            replacements[u'{math_expression}'] = self.__to_text(math_data['expression'])
            replacements[u'{math_answer}'] = self.__to_text(str(math_data['answer']))

        if challenge_type == 'pow_hash':
            seed = self.__pow_seed(site_name, token)
            difficulty = self.__safe_int(setting.get('pow_difficulty'), 3, 1, 5)
            replacements[u'{pow_seed}'] = self.__to_text(seed)
            replacements[u'{pow_difficulty}'] = self.__to_text(str(difficulty))

        for key, value in replacements.items():
            template = template.replace(key, value)
        return template

    def __build_challenge_script(self, challenge_type, site_name, setting, cookie_name, token, ttl, delay):
        common = (
            'var cookieName=%s,token=%s,ttl=%d,delay=%d;'
            'document.getElementById("t").textContent=%s;'
            'document.getElementById("m").textContent=%s;'
            'function state(v){var el=document.getElementById("state");if(el){el.textContent=v||"";}}'
            'function finish(v){var expires=new Date(Date.now()+ttl*1000).toUTCString();document.cookie=cookieName+"="+v+"; Max-Age="+ttl+"; expires="+expires+"; Path=/; SameSite=Lax";location.reload();}'
            'function simpleHash(s){var h=2166136261;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h+=(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24);}return ("00000000"+(h>>>0).toString(16)).slice(-8);}'
        ) % (
            self.__json_value(cookie_name),
            self.__json_value(token),
            ttl,
            delay,
            self.__json_value(setting.get('challenge_title') or self.__default_site_setting['challenge_title']),
            self.__json_value(setting.get('challenge_text') or self.__default_site_setting['challenge_text'])
        )

        if challenge_type == 'fingerprint':
            return common + (
                'function canvasSig(){try{var c=document.createElement("canvas"),x=c.getContext("2d");x.textBaseline="top";x.font="14px Arial";x.fillText("bt-js-challenge",2,2);return c.toDataURL();}catch(e){return "no-canvas";}}'
                'setTimeout(function(){var fp=[navigator.userAgent,navigator.language,navigator.platform,navigator.hardwareConcurrency||0,screen.width+"x"+screen.height,screen.colorDepth,new Date().getTimezoneOffset(),canvasSig()].join("|");finish(token+".fp."+simpleHash(fp));},delay);'
            )

        if challenge_type == 'captcha':
            code = self.__captcha_code(setting, token)
            return common + (
                'var captchaCode=%s;state("请输入页面验证码后继续访问");'
                'document.getElementById("captchaForm").onsubmit=function(e){e.preventDefault();var v=(document.getElementById("captchaAnswer").value||"").toUpperCase().replace(/\\s+/g,"");'
                'if(v===captchaCode){finish(token+".captcha."+captchaCode.toLowerCase());return;}document.getElementById("captchaError").textContent="验证码错误，请重新输入";};'
            ) % self.__json_value(code)

        if challenge_type == 'arithmetic':
            math_data = self.__arithmetic_challenge(site_name, token)
            return common + (
                'setTimeout(function(){var answer=%s;state("已完成算术校验");finish(token+".math."+answer);},delay);'
            ) % math_data['expression']

        if challenge_type == 'pow_hash':
            seed = self.__pow_seed(site_name, token)
            difficulty = self.__safe_int(setting.get('pow_difficulty'), 3, 1, 5)
            return common + (
                'var seed=%s,difficulty=%d,target=new Array(difficulty+1).join("0");'
                'function hex(buf){return Array.prototype.map.call(new Uint8Array(buf),function(x){return ("00"+x.toString(16)).slice(-2);}).join("");}'
                'function digest(v){if(window.crypto&&crypto.subtle&&window.TextEncoder){return crypto.subtle.digest("SHA-256",new TextEncoder().encode(v)).then(hex);}return Promise.resolve(simpleHash(v));}'
                'function pause(){return new Promise(function(r){setTimeout(r,0);});}'
                'setTimeout(function(){(async function(){var nonce=0;while(true){var h=await digest(seed+":"+nonce);if(h.substr(0,difficulty)===target){finish(token+".pow."+nonce+"."+h);return;}nonce++;if(nonce%%250===0){state("正在计算 Hash: "+nonce);await pause();}}}()).catch(function(){state("Hash 计算失败，请刷新重试");});},delay);'
            ) % (self.__json_value(seed), difficulty)

        return common + 'setTimeout(function(){finish(token+".basic");},delay);'

    def __challenge_extra_body(self, challenge_type, setting):
        if challenge_type != 'captcha':
            return ''
        code = self.__captcha_code(setting, self.__to_text(setting.get('token', '')))
        image_src = self.__captcha_image_data_uri(code, self.__to_text(setting.get('token', '')))
        return (
            '<form id="captchaForm"><img class="captcha-img" src="%s" alt="captcha">'
            '<div><input id="captchaAnswer" class="captcha-input" maxlength="8" autocomplete="off">'
            '<button class="captcha-btn" type="submit">验证</button></div><div id="captchaError" class="error"></div></form>'
        ) % self.__html_escape(image_src)

    def __cookie_pass_pattern(self, site_name, setting, token):
        token_pattern = re.escape(self.__to_text(token))
        challenge_type = self.__clean_challenge_type(setting.get('challenge_type'))
        if challenge_type == 'fingerprint':
            return token_pattern + r'\.fp\.[a-f0-9]{8,64}'
        if challenge_type == 'captcha':
            return token_pattern + r'\.captcha\.' + re.escape(self.__captcha_code(setting, token).lower())
        if challenge_type == 'arithmetic':
            return token_pattern + r'\.math\.' + self.__to_text(self.__arithmetic_challenge(site_name, token)['answer'])
        if challenge_type == 'pow_hash':
            return token_pattern + r'\.pow\.[0-9]+\.[a-f0-9]{8,64}'
        return token_pattern + r'\.basic'

    def __normalize_setting(self, args, old_setting):
        setting = dict(old_setting)
        old_challenge_type = self.__clean_challenge_type(old_setting.get('challenge_type'))
        setting['enabled'] = self.__to_bool(self.__get_arg(args, 'enabled', setting.get('enabled', False)))
        setting['challenge_type'] = self.__clean_challenge_type(self.__get_arg(args, 'challenge_type', setting.get('challenge_type')))
        setting['cookie_ttl'] = self.__safe_int(self.__get_arg(args, 'cookie_ttl', setting.get('cookie_ttl')), 3600, 60, 86400)
        setting['challenge_delay'] = self.__safe_int(self.__get_arg(args, 'challenge_delay', setting.get('challenge_delay')), 600, 0, 5000)
        setting['pow_difficulty'] = self.__safe_int(self.__get_arg(args, 'pow_difficulty', setting.get('pow_difficulty')), 3, 1, 5)
        setting['challenge_title'] = self.__clean_text(self.__get_arg(args, 'challenge_title', setting.get('challenge_title')), 40)
        setting['challenge_text'] = self.__clean_text(self.__get_arg(args, 'challenge_text', setting.get('challenge_text')), 120)
        setting['exclude_ext'] = self.__clean_ext_list(self.__get_arg(args, 'exclude_ext', setting.get('exclude_ext')))
        setting['ip_whitelist'] = self.__normalize_ip_whitelist(self.__get_arg(args, 'ip_whitelist', setting.get('ip_whitelist', [])))
        if not setting.get('challenge_title'):
            setting['challenge_title'] = self.__default_site_setting['challenge_title']
        if not setting.get('challenge_text'):
            setting['challenge_text'] = self.__default_site_setting['challenge_text']
        if not setting.get('token') or setting.get('challenge_type') != old_challenge_type:
            setting['token'] = uuid.uuid4().hex
        return setting

    def __get_site_setting(self, site_name):
        config = self.__get_config()
        site_settings = config.setdefault('sites', {})
        setting = dict(self.__default_site_setting)
        setting.update(site_settings.get(site_name, {}))
        changed = False
        if setting.get('challenge_title') == self.__legacy_challenge_title:
            setting['challenge_title'] = self.__default_site_setting['challenge_title']
            changed = True
        if setting.get('challenge_text') == self.__legacy_challenge_text:
            setting['challenge_text'] = self.__default_site_setting['challenge_text']
            changed = True
        if 'cookie_name' in setting:
            del setting['cookie_name']
            changed = True
        if not setting.get('token'):
            setting['token'] = uuid.uuid4().hex
            changed = True
        if changed:
            site_settings[site_name] = setting
            self.__write_config(config)
        setting['cookie_name'] = self.__cookie_name(site_name)
        return setting

    def __list_sites(self):
        try:
            return public.M('sites').field('id,name,path,status,ps,addtime').order('id desc').select()
        except Exception:
            return None

    def __get_site_by_name(self, site_name):
        site_list = self.__list_sites()
        if not site_list:
            return None
        for site in site_list:
            if self.__to_text(site.get('name', '')) == site_name:
                return site
        return None

    def __site_conf_path(self, site_name):
        return os.path.join(self.__nginx_conf_dir, site_name + '.conf')

    def __rule_path(self, site_name):
        safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', site_name).strip('_')[:80]
        if not safe_name:
            safe_name = 'site'
        return self.__nginx_path(os.path.join(self.__rule_dir, safe_name + '_' + self.__site_hash(site_name)[:10] + '.conf'))

    def __guard_rule_path(self, site_name):
        safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', site_name).strip('_')[:80]
        if not safe_name:
            safe_name = 'site'
        return self.__nginx_path(os.path.join(self.__rule_dir, safe_name + '_' + self.__site_hash(site_name)[:10] + '_guard.conf'))

    def __challenge_log_path(self, site_name, status):
        safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', site_name).strip('_')[:80]
        if not safe_name:
            safe_name = 'site'
        status = re.sub(r'[^a-z_]+', '', self.__to_text(status).lower()) or 'challenge'
        return self.__nginx_path(os.path.join(self.__access_log_dir, safe_name + '_' + self.__site_hash(site_name)[:10] + '_' + status + '.log'))

    def __challenge_log_files(self):
        result = []
        if not os.path.isdir(self.__access_log_dir):
            return result
        try:
            for filename in os.listdir(self.__access_log_dir):
                if filename.endswith('.log'):
                    result.append(os.path.join(self.__access_log_dir, filename))
        except Exception:
            pass
        return result

    def __cookie_name(self, site_name):
        return self.__runtime_prefix + self.__site_hash(site_name)[:10]

    def __site_hash(self, site_name):
        raw = self.__to_text(site_name)
        if isinstance(raw, text_type):
            raw = raw.encode('utf-8')
        return hashlib.md5(raw).hexdigest()

    def __build_include_block(self, rule_path):
        return '\n    {0}\n    include {1};\n    {2}\n'.format(self.__marker_start, rule_path, self.__marker_end)

    def __replace_include_block(self, conf_body, include_block):
        pattern = re.compile(r'\n?\s*' + re.escape(self.__marker_start) + r'\n.*?' + re.escape(self.__marker_end) + r'\n?', re.S)
        if pattern.search(conf_body):
            return pattern.sub(include_block, conf_body)
        return conf_body

    def __remove_include_block(self, conf_body):
        pattern = re.compile(r'\n?\s*' + re.escape(self.__marker_start) + r'\n.*?' + re.escape(self.__marker_end) + r'\n?', re.S)
        return pattern.sub('\n', conf_body)

    def __remove_location_guard_block(self, conf_body):
        pattern = re.compile(r'\n?\s*' + re.escape(self.__location_marker_start) + r'\n.*?' + re.escape(self.__location_marker_end) + r'\n?', re.S)
        return pattern.sub('\n', conf_body)

    def __insert_include_block(self, conf_body, include_block):
        match = re.search(r'(^\s*server\s*(?:\n\s*)?\{\s*\n?)', conf_body, re.M)
        if not match:
            return None
        return conf_body[:match.end()] + include_block + conf_body[match.end():]

    def __insert_location_guard_block(self, conf_body, guard_path):
        pattern = re.compile(r'(^[ \t]*location\s+/\s*(?:\n\s*)?\{\s*\n?)', re.M)
        match = pattern.search(conf_body)
        if not match:
            return None
        indent_match = re.match(r'^([ \t]*)', match.group(1))
        base_indent = indent_match.group(1) if indent_match else '    '
        inner_indent = base_indent + '    '
        block = '{0}{1}\n{0}include {2};\n{0}{3}\n'.format(
            inner_indent,
            self.__location_marker_start,
            guard_path,
            self.__location_marker_end
        )
        return conf_body[:match.end()] + block + conf_body[match.end():]

    def __nginx_include_exists(self, site_name):
        conf_body = self.__read_text(self.__site_conf_path(site_name))
        if not conf_body:
            return False
        return self.__marker_start in conf_body and self.__rule_path(site_name) in conf_body

    def __build_ext_regex(self, ext_list):
        exts = []
        for item in self.__to_text(ext_list).split(','):
            ext = item.strip().strip('.').lower()
            ext = re.sub(r'[^a-z0-9]+', '', ext)
            if ext and ext not in exts:
                exts.append(re.escape(ext))
        return '|'.join(exts)

    def __clean_ext_list(self, ext_list):
        exts = []
        for item in self.__to_text(ext_list).split(','):
            ext = item.strip().strip('.').lower()
            ext = re.sub(r'[^a-z0-9]+', '', ext)
            if ext and ext not in exts:
                exts.append(ext)
        if not exts:
            return self.__default_site_setting['exclude_ext']
        return ','.join(exts)

    def __clean_text(self, value, max_len):
        value = self.__to_text(value).strip()
        value = re.sub(r'[\r\n\t]+', ' ', value)
        return value[:max_len]

    def __clean_challenge_type(self, value):
        value = self.__to_text(value).strip()
        for item in self.__challenge_types:
            if item.get('value') == value:
                return value
        return self.__default_site_setting['challenge_type']

    def __validate_ip(self, ip):
        raw = self.__to_text(ip).strip()
        if '/' in raw:
            ip_part, mask_str = raw.split('/', 1)
            try:
                mask = int(mask_str)
                if mask < 0 or mask > 32:
                    return None
            except Exception:
                return None
        else:
            ip_part = raw
            mask = 32
        octets = ip_part.split('.')
        if len(octets) != 4:
            return None
        for val in octets:
            try:
                num = int(val)
                if num < 0 or num > 255:
                    return None
            except Exception:
                return None
        return raw

    def __normalize_ip_whitelist(self, raw):
        if isinstance(raw, list):
            entries = raw
        else:
            entries = re.split(r'[,\n\s]+', self.__to_text(raw))
        result = []
        for entry in entries:
            entry = self.__to_text(entry).strip()
            validated = self.__validate_ip(entry)
            if validated and validated not in result:
                result.append(validated)
        return result

    def __cidr_to_nginx_pattern(self, cidr):
        if '/' not in cidr:
            return None
        ip_part, mask_str = cidr.split('/', 1)
        try:
            mask = int(mask_str)
        except Exception:
            return None
        if mask < 0 or mask > 32:
            return None
        octets = ip_part.split('.')
        if len(octets) != 4:
            return None
        prefix = ''
        for idx in range(4):
            if mask >= (idx + 1) * 8:
                prefix += re.escape(octets[idx]) + r'\.'
            else:
                break
        return r'^' + prefix if prefix else None

    def __captcha_code(self, setting, token):
        raw = self.__to_text(setting.get('captcha_code', '')).upper()
        raw = re.sub(r'[^A-Z0-9]+', '', raw)
        if 4 <= len(raw) <= 8:
            return raw
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        digest = self.__site_hash(self.__to_text(token) + ':captcha').upper()
        code = []
        for index in range(0, 10, 2):
            code.append(chars[int(digest[index:index + 2], 16) % len(chars)])
        return ''.join(code)

    def __captcha_image_data_uri(self, code, token):
        digest = self.__site_hash(self.__to_text(token) + ':' + self.__to_text(code) + ':captcha-image')
        colors = ['#111827', '#1d4ed8', '#047857', '#b45309', '#be123c']
        noise_colors = ['#cbd5e1', '#d1d5db', '#bfdbfe', '#bbf7d0']
        text_parts = []
        for index, char in enumerate(self.__to_text(code)):
            seed = int(digest[index * 2:index * 2 + 2], 16)
            x = 22 + index * 25
            y = 35 + (seed % 7) - 3
            rotate = (seed % 25) - 12
            color = colors[seed % len(colors)]
            text_parts.append(
                '<text x="{0}" y="{1}" fill="{2}" transform="rotate({3} {0} {1})">{4}</text>'.format(
                    x, y, color, rotate, self.__html_escape(char)
                )
            )

        line_parts = []
        for index in range(6):
            seed = int(digest[10 + index * 2:12 + index * 2], 16)
            x1 = seed % 168
            y1 = (seed * 3) % 52
            x2 = (seed * 7) % 168
            y2 = (seed * 11) % 52
            color = noise_colors[index % len(noise_colors)]
            line_parts.append('<line x1="{0}" y1="{1}" x2="{2}" y2="{3}" stroke="{4}" stroke-width="1"/>'.format(x1, y1, x2, y2, color))

        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="168" height="52" viewBox="0 0 168 52">'
            '<rect width="168" height="52" rx="4" fill="#f8fafc"/>'
            '{0}<g font-family="Arial, sans-serif" font-size="25" font-weight="700" letter-spacing="2">{1}</g>'
            '</svg>'
        ).format(''.join(line_parts), ''.join(text_parts))
        raw = svg.encode('utf-8')
        if base64 is not None:
            encoded = base64.b64encode(raw)
            if not isinstance(encoded, text_type):
                encoded = encoded.decode('ascii')
            return 'data:image/svg+xml;base64,' + encoded
        return 'data:image/svg+xml;utf8,' + self.__url_encode_svg(svg)

    def __arithmetic_challenge(self, site_name, token):
        digest = self.__site_hash(self.__to_text(site_name) + ':' + self.__to_text(token) + ':math')
        seed = int(digest[:8], 16)
        op_index = seed % 3
        if op_index == 0:
            left = seed % 90 + 10
            right = (seed // 97) % 90 + 10
            return {'expression': '%d+%d' % (left, right), 'answer': left + right}
        if op_index == 1:
            left = seed % 90 + 20
            right = (seed // 97) % 40 + 1
            if right > left:
                left, right = right, left
            return {'expression': '%d-%d' % (left, right), 'answer': left - right}
        left = seed % 12 + 2
        right = (seed // 97) % 12 + 2
        return {'expression': '%d*%d' % (left, right), 'answer': left * right}

    def __pow_seed(self, site_name, token):
        raw = self.__to_text(site_name) + ':' + self.__to_text(token) + ':pow'
        if isinstance(raw, text_type):
            raw = raw.encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def __json_value(self, value):
        return json.dumps(self.__to_text(value), ensure_ascii=False).replace('</', '<\\/').replace('$', '\\u0024')

    def __html_escape(self, value):
        value = self.__to_text(value)
        return (value.replace('&', '&amp;')
                     .replace('<', '&lt;')
                     .replace('>', '&gt;')
                     .replace('"', '&quot;')
                     .replace("'", '&#39;')
                     .replace('$', '&#36;'))

    def __url_encode_svg(self, value):
        value = self.__to_text(value)
        safe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~'
        result = []
        for char in value:
            if char in safe:
                result.append(char)
            else:
                raw = char.encode('utf-8')
                for item in raw:
                    if not isinstance(item, int):
                        item = ord(item)
                    result.append('%{0:02X}'.format(item))
        return ''.join(result)

    def __test_nginx(self):
        if not os.path.exists(self.__nginx_bin):
            return self.__fail(u'未检测到 Nginx：' + self.__nginx_bin)
        return self.__exec(self.__nginx_bin + ' -t')

    def __reload_nginx(self):
        if os.path.exists('/etc/init.d/nginx'):
            return self.__exec('/etc/init.d/nginx reload')
        return self.__exec(self.__nginx_bin + ' -s reload')

    def __exec(self, command):
        try:
            cmd_list = shlex.split(command) if isinstance(command, str) else list(command)
            process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = process.communicate()[0]
            if not isinstance(output, text_type):
                output = output.decode('utf-8', 'ignore')
            output = output.strip()
            if process.returncode != 0:
                return self.__fail(output or ' '.join(cmd_list))
            return {'status': True, 'msg': output}
        except Exception as ex:
            return self.__fail(self.__to_text(ex))

    def __get_config(self):
        now = time.time()
        if self.__config is not None and (now - self.__config_cache_time) < self.__config_cache_ttl:
            return self.__config
        body = self.__read_text(self.__config_file)
        if not body:
            self.__config = {'sites': {}}
            self.__config_cache_time = now
            return self.__config
        try:
            self.__config = json.loads(body)
        except Exception:
            self.__config = {'sites': {}}
        self.__config.setdefault('sites', {})
        self.__config_cache_time = now
        return self.__config

    def __write_config(self, config):
        self.__config = config
        self.__config_cache_time = 0
        return self.__write_text(self.__config_file, json.dumps(config, ensure_ascii=False, indent=2))

    def __read_logs(self):
        body = self.__read_text(self.__log_file)
        if not body:
            return []
        try:
            logs = json.loads(body)
            if isinstance(logs, list):
                return logs
        except Exception:
            pass
        return []

    def __write_logs(self, logs):
        return self.__write_text(self.__log_file, json.dumps(logs, ensure_ascii=False, indent=2))

    def __read_challenge_logs(self):
        result = []
        for site_name, setting in self.__challenge_sites_for_logs():
            challenge_type = self.__clean_challenge_type(setting.get('challenge_type'))
            type_title = self.__challenge_type_title(challenge_type)
            result.extend(self.__parse_challenge_log_file(
                self.__challenge_log_path(site_name, 'challenge'),
                site_name,
                type_title,
                u'未通过'
            ))
            result.extend(self.__parse_challenge_log_file(
                self.__challenge_log_path(site_name, 'passed'),
                site_name,
                type_title,
                u'通过'
            ))
        result.sort(key=lambda item: item.get('timestamp', 0), reverse=True)
        result = self.__filter_challenge_attempt_logs(result)
        return self.__dedupe_challenge_logs(result)

    def __challenge_sites_for_logs(self):
        sites = {}
        config_sites = self.__get_config().get('sites', {})
        for site_name, setting in config_sites.items():
            sites[self.__to_text(site_name)] = dict(setting)
        if public is not None:
            site_list = self.__list_sites() or []
            for site in site_list:
                site_name = self.__to_text(site.get('name', ''))
                if site_name and site_name not in sites:
                    sites[site_name] = self.__get_site_setting(site_name)
        return sorted(sites.items(), key=lambda item: item[0])

    def __parse_challenge_log_file(self, filename, site_name, type_title, status):
        if not os.path.exists(filename):
            return []
        try:
            with codecs.open(filename, 'r', 'utf-8', errors='ignore') as fp:
                lines = fp.readlines()[-500:]
        except TypeError:
            try:
                with open(filename, 'rb') as fp:
                    lines = [line.decode('utf-8', 'ignore') for line in fp.readlines()[-500:]]
            except Exception:
                return []
        except Exception:
            return []

        result = []
        for line in lines:
            item = self.__parse_combined_log_line(line)
            if not item:
                continue
            item['site'] = site_name
            item['type'] = type_title
            item['status'] = status
            result.append(item)
        return result

    def __parse_combined_log_line(self, line):
        pattern = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<code>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')
        match = pattern.search(self.__to_text(line).strip())
        if not match:
            return None
        log_time = match.group('time')
        return {
            'ip': match.group('ip'),
            'time': self.__format_nginx_time(log_time),
            'raw_time': log_time,
            'timestamp': self.__parse_nginx_time(log_time),
            'request': match.group('request'),
            'code': match.group('code'),
            'ua': match.group('ua')
        }

    def __dedupe_challenge_logs(self, logs):
        groups = []
        for item in logs:
            key = self.__challenge_log_key(item)
            timestamp = int(item.get('timestamp', 0))
            matched = None
            for group in groups:
                if group.get('_key') == key and abs(int(group.get('timestamp', 0)) - timestamp) <= 5:
                    matched = group
                    break
            if not matched:
                new_item = dict(item)
                new_item['_key'] = key
                new_item['count'] = 1
                groups.append(new_item)
                continue
            matched['count'] = int(matched.get('count', 1)) + 1
            if item.get('status') == u'通过':
                matched['status'] = u'通过'
            if timestamp > int(matched.get('timestamp', 0)):
                matched['timestamp'] = timestamp
                matched['time'] = item.get('time', matched.get('time', ''))
                matched['raw_time'] = item.get('raw_time', matched.get('raw_time', ''))
                matched['request'] = item.get('request', matched.get('request', ''))
                matched['code'] = item.get('code', matched.get('code', ''))
        groups.sort(key=lambda item: item.get('timestamp', 0), reverse=True)
        for item in groups:
            if '_key' in item:
                del item['_key']
        return groups

    def __filter_challenge_attempt_logs(self, logs):
        passed_times = {}
        now_time = int(time.time())
        for item in logs:
            if item.get('status') != u'通过':
                continue
            passed_times.setdefault(self.__challenge_log_key(item), []).append(int(item.get('timestamp', 0)))

        result = []
        for item in logs:
            if item.get('status') != u'未通过':
                result.append(item)
                continue
            timestamp = int(item.get('timestamp', 0))
            if self.__has_later_pass(passed_times.get(self.__challenge_log_key(item), []), timestamp):
                continue
            if timestamp > 0 and now_time - timestamp < self.__challenge_pending_grace:
                continue
            result.append(item)
        return result

    def __has_later_pass(self, passed_times, timestamp):
        if timestamp <= 0:
            return False
        for passed_time in passed_times:
            if timestamp <= passed_time and passed_time - timestamp <= self.__challenge_pass_window:
                return True
        return False

    def __challenge_log_key(self, item):
        return '|'.join([
            self.__to_text(item.get('ip', '')),
            self.__to_text(item.get('site', '')),
            self.__to_text(item.get('type', '')),
            self.__to_text(item.get('ua', ''))
        ])

    def __parse_nginx_time(self, value):
        try:
            return time.mktime(time.strptime(value.split()[0], '%d/%b/%Y:%H:%M:%S'))
        except Exception:
            return 0

    def __format_nginx_time(self, value):
        timestamp = self.__parse_nginx_time(value)
        if not timestamp:
            return self.__to_text(value)
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    def __challenge_type_title(self, value):
        for item in self.__challenge_types:
            if item.get('value') == value:
                return item.get('title')
        return u'Cookie延时挑战'

    def __append_log(self, action, site_name, detail):
        logs = self.__read_logs()
        logs.insert(0, {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'action': self.__to_text(action),
            'site': self.__to_text(site_name),
            'detail': self.__to_text(detail)
        })
        self.__write_logs(logs[:self.__max_log_rows])

    def __write_panel_log(self, message):
        if public is not None:
            try:
                public.WriteLog(u'JS挑战防火墙', self.__to_text(message))
            except Exception:
                pass

    def __ensure_storage(self):
        try:
            if not os.path.isdir(self.__plugin_path):
                os.makedirs(self.__plugin_path)
            if not os.path.isdir(self.__rule_dir):
                os.makedirs(self.__rule_dir)
            if not os.path.isdir(self.__access_log_dir):
                os.makedirs(self.__access_log_dir)
            if not os.path.isdir(self.__challenge_template_dir):
                os.makedirs(self.__challenge_template_dir)
            if not os.path.exists(self.__config_file):
                self.__write_text(self.__config_file, json.dumps({'sites': {}}, ensure_ascii=False, indent=2))
            if not os.path.exists(self.__log_file):
                self.__write_text(self.__log_file, '[]')
        except Exception:
            pass

    def __read_text(self, filename):
        try:
            with codecs.open(filename, 'r', 'utf-8') as fp:
                return fp.read()
        except Exception:
            return None

    def __write_text(self, filename, body):
        try:
            directory = os.path.dirname(filename)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with codecs.open(filename, 'w', 'utf-8') as fp:
                fp.write(self.__to_text(body))
            return True
        except Exception:
            return False

    def __nginx_quote(self, value):
        return self.__to_text(value).replace('\\', '\\\\').replace("'", "\\'")

    def __nginx_path(self, value):
        return self.__to_text(value).replace('\\', '/')

    def __build_nginx_body_lines(self, variable_prefix, body):
        chunks = self.__split_nginx_body(body, 1200)
        lines = []
        names = []
        for index, chunk in enumerate(chunks):
            name = '{0}_{1}'.format(variable_prefix, index)
            names.append('$' + name)
            lines.append("    set ${0} '{1}';".format(name, self.__nginx_quote(chunk)))
        return lines, ''.join(names)

    def __split_nginx_body(self, body, max_bytes):
        chunks = []
        current = []
        current_size = 0
        for char in self.__to_text(body):
            char_size = len(char.encode('utf-8'))
            if current and current_size + char_size > max_bytes:
                chunks.append(''.join(current))
                current = []
                current_size = 0
            current.append(char)
            current_size += char_size
        if current:
            chunks.append(''.join(current))
        return chunks or ['']

    def __safe_int(self, value, default, min_value, max_value):
        try:
            value = int(value)
        except Exception:
            value = default
        if value < min_value:
            return min_value
        if value > max_value:
            return max_value
        return value

    def __to_bool(self, value):
        if isinstance(value, bool):
            return value
        value = self.__to_text(value).lower()
        return value in ('1', 'true', 'yes', 'on', '开启', '启用')

    def __get_arg(self, args, key, default=None):
        if isinstance(args, dict):
            return args.get(key, default)
        if hasattr(args, key):
            return getattr(args, key)
        return default

    def __to_text(self, value):
        if value is None:
            return u''
        if isinstance(value, text_type):
            return value
        try:
            return value.decode('utf-8', 'ignore')
        except Exception:
            return text_type(value)

    def __fail(self, message):
        return {'status': False, 'msg': self.__to_text(message)}