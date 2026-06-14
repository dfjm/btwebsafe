/**
 * 星辰云防火墙 - 宝塔面板插件前端脚本
 * 版本: 1.2
 */

(function () {
    'use strict';

    /* ---- 工具函数 ---- */
    function htmlEscape(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function debounce(fn, delay) {
        var timer = null;
        return function () {
            var ctx = this, args = arguments;
            if (timer) clearTimeout(timer);
            timer = setTimeout(function () { timer = null; fn.apply(ctx, args); }, delay);
            return timer;
        };
    }

    function setButtonLoading(btn, isLoading) {
        if (isLoading) {
            btn._origText = btn.textContent;
            btn.textContent = btn._origText + '...';
            btn.classList.add('is-loading');
            btn.disabled = true;
        } else {
            btn.classList.remove('is-loading');
            btn.disabled = false;
            if (btn._origText !== undefined) btn.textContent = btn._origText;
        }
    }

    function requestPlugin(pluginName, functionName, args, callback, timeout) {
        if (!timeout) timeout = 3600 * 1000;
        $.ajax({
            type: 'POST',
            url: '/plugin?action=a&s=' + functionName + '&name=' + pluginName,
            data: args,
            timeout: timeout,
            success: function (rdata) {
                if (callback) callback(rdata);
            },
            error: function () {
                layer.msg('插件请求失败，请检查网络或面板状态', { icon: 2 });
            }
        });
    }

    /* ---- 主对象 ---- */
    window.bt_js_challenge = {
        sites: [],
        filterText: '',
        filterStatus: 'all',
        selectedSites: {},
        isBatchMode: false,
        challengeTypes: [
            { value: 'cookie_delay', title: 'Cookie延时挑战' },
            { value: 'fingerprint',   title: '浏览器指纹挑战' },
            { value: 'captcha',       title: '验证码挑战' },
            { value: 'arithmetic',    title: '算术挑战' },
            { value: 'pow_hash',      title: 'PoW/Hash计算挑战' }
        ],

        /* ======== 站点管理 ======== */
        getSites: function () {
            var self = this;
            $('.plugin_body').html('<div class="jsfw-empty">正在加载...</div>');
            requestPlugin('xcy_safe', 'get_sites', {}, function (rdata) {
                if (!rdata.status) {
                    layer.msg(rdata.msg || '读取网站列表失败', { icon: 2 });
                    return;
                }
                self.sites = rdata.sites || [];
                self.challengeTypes = rdata.challenge_types || self.challengeTypes;
                self.selectedSites = {};
                self.isBatchMode = false;
                self.renderSites();
            });
        },

        renderSites: function () {
            var stats = this.getStats();
            var list = '';
            var visible = 0;
            for (var i = 0; i < this.sites.length; i++) {
                if (!this.matchFilter(this.sites[i])) continue;
                list += this.renderSiteItem(this.sites[i], i);
                visible++;
            }
            if (!list) {
                list = '<div class="jsfw-empty">暂无匹配网站</div>';
            }

            var batchClass = Object.keys(this.selectedSites).length > 0 ? ' visible' : '';
            var batchCount = Object.keys(this.selectedSites).length;
            var self = this;
            var allChecked = this.sites.length > 0 && this.sites.every(function (s, i) {
                return !self.matchFilter(s) || self.selectedSites[i];
            });

            var body =
                '<div class="jsfw-topbar">' +
                    '<div class="jsfw-heading">' +
                        '<h3 class="jsfw-title">站点 JS 挑战设置</h3>' +
                        '<div class="jsfw-subtitle">当前显示 ' + visible + ' / ' + this.sites.length + ' 个网站</div>' +
                    '</div>' +
                    '<div class="jsfw-actions">' +
                        '<label style="font-size:12px;color:#5d6b82;cursor:pointer;white-space:nowrap;">' +
                            '<input type="checkbox" id="jsfw-select-all" onchange="bt_js_challenge.toggleSelectAll(this)" style="margin-right:4px;accent-color:#16a36a;">全选' +
                        '</label>' +
                        '<input class="bt-input-text jsfw-search" type="text" placeholder="搜索网站或路径" value="' + htmlEscape(this.filterText) + '" oninput="bt_js_challenge.onSearchInput(this)">' +
                        '<select class="bt-input-text jsfw-filter" onchange="bt_js_challenge.setFilterStatus(this.value)">' +
                            '<option value="all"' + this.selectedFilter('all') + '>全部</option>' +
                            '<option value="enabled"' + this.selectedFilter('enabled') + '>已启用</option>' +
                            '<option value="disabled"' + this.selectedFilter('disabled') + '>未启用</option>' +
                            '<option value="unsupported"' + this.selectedFilter('unsupported') + '>不支持</option>' +
                        '</select>' +
                        '<button class="btn btn-default btn-sm" onclick="bt_js_challenge.getSites()">刷新</button>' +
                        '<button class="btn btn-default btn-sm" onclick="bt_js_challenge.exportConfig()" title="导出配置">导出</button>' +
                        '<button class="btn btn-default btn-sm" onclick="bt_js_challenge.showImport()" title="导入配置">导入</button>' +
                    '</div>' +
                '</div>' +
                '<div class="jsfw-batch-bar' + batchClass + '">' +
                    '<span class="jsfw-batch-count">已选 ' + batchCount + ' 个站点</span>' +
                    '<button class="btn btn-success btn-xs" onclick="bt_js_challenge.batchEnable()">批量启用</button>' +
                    '<button class="btn btn-danger btn-xs" onclick="bt_js_challenge.batchDisable()">批量关闭</button>' +
                    '<button class="btn btn-default btn-xs" onclick="bt_js_challenge.clearSelection()">取消选择</button>' +
                '</div>' +
                '<div class="jsfw-stats">' +
                    this.renderStat('全部网站', stats.total, '') +
                    this.renderStat('已启用', stats.enabled, 'active') +
                    this.renderStat('未启用', stats.disabled, '') +
                    this.renderStat('不支持', stats.unsupported, 'warn') +
                '</div>' +
                '<div class="jsfw-site-list">' + list + '</div>' +
                '<div id="jsfw-import-area" class="jsfw-import-area" style="display:none;"></div>';

            $('.plugin_body').html(body);
            if (allChecked) {
                $('#jsfw-select-all').prop('checked', true);
                $('#jsfw-select-all').prop('indeterminate', false);
            } else if (batchCount > 0) {
                $('#jsfw-select-all').prop('checked', false);
                $('#jsfw-select-all').prop('indeterminate', true);
            }
        },

        renderSiteItem: function (item, index) {
            var setting = item.setting || {};
            var enabled = !!setting.enabled;
            var active = !!item.active;
            var checked = enabled ? ' checked="checked"' : '';
            var disabledAttr = item.supported ? '' : ' disabled="disabled"';
            var typeTitle = this.typeTitle(setting.challenge_type || 'cookie_delay');
            var stateClass = 'jsfw-site has-check';
            if (enabled) stateClass += ' is-active';
            if (this.selectedSites[index]) stateClass += ' is-selected';
            if (!item.supported) stateClass += ' is-unsupported';

            var statusClass = 'jsfw-pill';
            var statusText = '未启用';
            if (enabled && active) { statusClass += ' ok'; statusText = '已启用'; }
            if (enabled && !active) { statusClass += ' warn'; statusText = '未生效'; }
            if (!item.supported) { statusClass += ' warn'; statusText = '不支持'; }

            var checkedStr = this.selectedSites[index] ? ' checked="checked"' : '';

            return '<div class="' + stateClass + '" data-index="' + index + '">' +
                '<input class="jsfw-site-check" type="checkbox"' + checkedStr + ' onchange="bt_js_challenge.toggleSiteSelect(' + index + ', this)" onclick="event.stopPropagation();">' +
                '<div class="jsfw-site-head">' +
                    '<div>' +
                        '<span class="jsfw-site-name" title="' + htmlEscape(item.name) + '">' + htmlEscape(item.name) + '</span>' +
                        '<span class="jsfw-site-path" title="' + htmlEscape(item.path || '') + '">' + htmlEscape(item.path || '-') + '</span>' +
                        '<div class="jsfw-site-meta">' +
                            '<span class="' + statusClass + '">' + statusText + '</span>' +
                            '<span class="jsfw-pill">' + htmlEscape(typeTitle) + '</span>' +
                            '<span class="jsfw-pill">' + htmlEscape(setting.cookie_ttl || 3600) + ' 秒</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="jsfw-head-actions">' +
                        '<label class="jsfw-switch">' +
                            '<input class="jsfw-enabled" type="checkbox"' + checked + disabledAttr + '>' +
                            '<span class="jsfw-slider"></span><span>JS挑战</span>' +
                        '</label>' +
                        '<button class="btn btn-success btn-xs" id="jsfw-btn-' + index + '" onclick="bt_js_challenge.saveSite(' + index + ', this)"' + disabledAttr + '>保存</button>' +
                        '<button class="btn btn-default btn-xs" onclick="bt_js_challenge.disableSite(' + index + ')"' + disabledAttr + '>关闭</button>' +
                    '</div>' +
                '</div>' +
                '<div class="jsfw-site-body"><div class="jsfw-grid">' +
                    this.renderSelectField('挑战类型', 'jsfw-type', this.renderTypeOptions(setting.challenge_type || 'cookie_delay'), disabledAttr) +
                    this.renderNumberField('通过有效期', 'jsfw-ttl', setting.cookie_ttl || 3600, 60, 86400, '秒', disabledAttr) +
                    this.renderNumberField('挑战延时', 'jsfw-delay', setting.challenge_delay || 600, 0, 5000, '毫秒', disabledAttr) +
                    this.renderNumberField('PoW难度', 'jsfw-pow', setting.pow_difficulty || 3, 1, 5, '', disabledAttr) +
                    this.renderTextInput('页面标题', 'jsfw-title', setting.challenge_title || '星辰云IDC安全验证', 40, disabledAttr) +
                    this.renderTextInput('提示文案', 'jsfw-text', setting.challenge_text || '星辰云IDC正在检查你的浏览器...', 120, disabledAttr) +
                    this.renderTextInput('放行扩展名', 'jsfw-ext', setting.exclude_ext || '', 180, disabledAttr, 'wide') +
                    this.renderTextareaField('IP白名单', 'jsfw-whitelist', (setting.ip_whitelist || []).join('\n'), 1000, disabledAttr, 'wide') +
                '</div></div>' +
            '</div>';
        },

        /* ---- 通用渲染函数 ---- */
        renderStat: function (label, value, cls) {
            return '<div class="jsfw-stat ' + cls + '"><span class="jsfw-stat-label">' + label + '</span><span class="jsfw-stat-value">' + value + '</span></div>';
        },

        renderSelectField: function (label, cls, options, disabled) {
            return '<label class="jsfw-field"><span class="jsfw-label">' + label + '</span><select class="bt-input-text jsfw-control ' + cls + '"' + disabled + '>' + options + '</select></label>';
        },

        renderNumberField: function (label, cls, value, min, max, unit, disabled) {
            var unitHtml = unit ? '<span class="jsfw-unit">' + unit + '</span>' : '';
            return '<label class="jsfw-field"><span class="jsfw-label">' + label + '</span><span class="jsfw-inline-unit"><input class="bt-input-text jsfw-control ' + cls + '" type="number" min="' + min + '" max="' + max + '" value="' + htmlEscape(value) + '"' + disabled + '>' + unitHtml + '</span></label>';
        },

        renderTextInput: function (label, cls, value, maxlength, disabled, extraClass) {
            return '<label class="jsfw-field ' + (extraClass || '') + '"><span class="jsfw-label">' + label + '</span><input class="bt-input-text jsfw-control ' + cls + '" type="text" maxlength="' + maxlength + '" value="' + htmlEscape(value) + '"' + disabled + '></label>';
        },

        renderTextareaField: function (label, cls, value, maxlength, disabled, extraClass) {
            return '<label class="jsfw-field ' + (extraClass || '') + '"><span class="jsfw-label">' + label + '</span><textarea class="bt-input-text jsfw-control jsfw-textarea ' + cls + '" maxlength="' + maxlength + '" placeholder="每行一个IP，支持CIDR（如 10.0.0.0/8）"' + disabled + '>' + htmlEscape(value) + '</textarea></label>';
        },

        renderTypeOptions: function (value) {
            var html = '';
            for (var i = 0; i < this.challengeTypes.length; i++) {
                var item = this.challengeTypes[i];
                var selected = item.value === value ? ' selected="selected"' : '';
                html += '<option value="' + htmlEscape(item.value) + '"' + selected + '>' + htmlEscape(item.title) + '</option>';
            }
            return html;
        },

        typeTitle: function (value) {
            for (var i = 0; i < this.challengeTypes.length; i++) {
                if (this.challengeTypes[i].value === value) return this.challengeTypes[i].title;
            }
            return 'Cookie延时挑战';
        },

        /* ---- 统计与筛选 ---- */
        getStats: function () {
            var stats = { total: this.sites.length, enabled: 0, disabled: 0, unsupported: 0 };
            for (var i = 0; i < this.sites.length; i++) {
                var item = this.sites[i];
                if (!item.supported) stats.unsupported++;
                else if (item.setting && item.setting.enabled) stats.enabled++;
                else stats.disabled++;
            }
            return stats;
        },

        matchFilter: function (item) {
            var text = this.filterText.toLowerCase();
            var setting = item.setting || {};
            if (text) {
                var haystack = String(item.name || '').toLowerCase() + ' ' + String(item.path || '').toLowerCase();
                if (haystack.indexOf(text) === -1) return false;
            }
            if (this.filterStatus === 'enabled') return !!(item.supported && setting.enabled);
            if (this.filterStatus === 'disabled') return !!(item.supported && !setting.enabled);
            if (this.filterStatus === 'unsupported') return !item.supported;
            return true;
        },

        onSearchInput: function (el) {
            var self = this;
            this.filterText = el.value || '';
            if (this._searchTimer) clearTimeout(this._searchTimer);
            this._searchTimer = setTimeout(function () {
                self.renderSites();
            }, 280);
        },

        setFilterStatus: function (value) {
            this.filterStatus = value || 'all';
            this.renderSites();
        },

        selectedFilter: function (value) {
            return this.filterStatus === value ? ' selected="selected"' : '';
        },

        /* ---- 批量选择 ---- */
        toggleSelectAll: function (el) {
            var checked = el.checked;
            this.selectedSites = {};
            if (checked) {
                for (var i = 0; i < this.sites.length; i++) {
                    if (!this.matchFilter(this.sites[i])) continue;
                    if (!this.sites[i].supported) continue;
                    this.selectedSites[i] = true;
                }
            }
            this.renderSites();
        },

        toggleSiteSelect: function (index, el) {
            if (el.checked) {
                this.selectedSites[index] = true;
            } else {
                delete this.selectedSites[index];
            }
            this.renderSites();
        },

        clearSelection: function () {
            this.selectedSites = {};
            this.renderSites();
        },

        getSelectedSiteNames: function () {
            var names = [];
            for (var i in this.selectedSites) {
                if (this.selectedSites.hasOwnProperty(i) && this.sites[i]) {
                    names.push(this.sites[i].name);
                }
            }
            return names;
        },

        /* ======== 站点操作 ======== */
        saveSite: function (index, btnEl) {
            var row = $('.jsfw-site[data-index="' + index + '"]');
            var item = this.sites[index];
            var args = {
                site_name: item.name,
                enabled: row.find('.jsfw-enabled').is(':checked') ? 1 : 0,
                challenge_type: row.find('.jsfw-type').val(),
                cookie_ttl: row.find('.jsfw-ttl').val(),
                challenge_delay: row.find('.jsfw-delay').val(),
                pow_difficulty: row.find('.jsfw-pow').val(),
                challenge_title: row.find('.jsfw-title').val(),
                challenge_text: row.find('.jsfw-text').val(),
                exclude_ext: row.find('.jsfw-ext').val(),
                ip_whitelist: row.find('.jsfw-whitelist').val()
            };
            if (btnEl) setButtonLoading(btnEl, true);
            var self = this;
            requestPlugin('xcy_safe', 'save_site', args, function (rdata) {
                if (btnEl) setButtonLoading(btnEl, false);
                layer.msg(rdata.msg || (rdata.status ? '保存成功' : '保存失败'), { icon: rdata.status ? 1 : 2 });
                self.getSites();
            }, 120000);
        },

        disableSite: function (index) {
            var self = this;
            var item = this.sites[index];
            layer.confirm(
                '确定关闭站点 <strong>' + htmlEscape(item.name) + '</strong> 的 JS 挑战防护？',
                { title: '关闭 JS 挑战', icon: 3, btn: ['确定关闭', '取消'] },
                function (layerIndex) {
                    layer.close(layerIndex);
                    var row = $('.jsfw-site[data-index="' + index + '"]');
                    row.find('.jsfw-enabled').prop('checked', false);
                    self.saveSite(index);
                }
            );
        },

        batchEnable: function () {
            var names = this.getSelectedSiteNames();
            if (names.length === 0) { layer.msg('请先选择站点', { icon: 0 }); return; }
            var self = this;
            layer.confirm(
                '确定对 ' + names.length + ' 个站点<strong>批量启用</strong> JS 挑战？',
                { title: '批量启用', icon: 3, btn: ['确定', '取消'] },
                function (layerIndex) {
                    layer.close(layerIndex);
                    requestPlugin('xcy_safe', 'batch_enable_sites', { site_names: names.join(',') }, function (rdata) {
                        layer.msg(rdata.msg || '批量操作完成', { icon: rdata.status ? 1 : 2 });
                        self.getSites();
                    }, 180000);
                }
            );
        },

        batchDisable: function () {
            var names = this.getSelectedSiteNames();
            if (names.length === 0) { layer.msg('请先选择站点', { icon: 0 }); return; }
            var self = this;
            layer.confirm(
                '确定对 ' + names.length + ' 个站点<strong>批量关闭</strong> JS 挑战？此操作不可恢复！',
                { title: '批量关闭', icon: 3, btn: ['确定关闭', '取消'] },
                function (layerIndex) {
                    layer.close(layerIndex);
                    requestPlugin('xcy_safe', 'batch_disable_sites', { site_names: names.join(',') }, function (rdata) {
                        layer.msg(rdata.msg || '批量操作完成', { icon: rdata.status ? 1 : 2 });
                        self.getSites();
                    }, 180000);
                }
            );
        },

        /* ======== 导入导出 ======== */
        exportConfig: function () {
            var self = this;
            requestPlugin('xcy_safe', 'export_config', {}, function (rdata) {
                if (!rdata.status || !rdata.data) {
                    layer.msg(rdata.msg || '导出失败', { icon: 2 });
                    return;
                }
                var blob = new Blob([rdata.data], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'bt-js-challenge-config-' + new Date().toISOString().slice(0, 10) + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                layer.msg('配置已导出', { icon: 1 });
            });
        },

        showImport: function () {
            if ($('#jsfw-import-area').is(':visible')) {
                $('#jsfw-import-area').hide();
                return;
            }
            var html =
                '<h4 style="margin:0 0 8px;">导入配置</h4>' +
                '<textarea id="jsfw-import-data" placeholder="粘贴之前导出的 JSON 配置数据..."></textarea>' +
                '<div style="margin-top:10px;display:flex;gap:8px;">' +
                    '<button class="btn btn-success btn-xs" onclick="bt_js_challenge.doImport()">确认导入</button>' +
                    '<button class="btn btn-default btn-xs" onclick="bt_js_challenge.hideImport()">取消</button>' +
                    '<span style="font-size:12px;color:#667085;line-height:28px;">导入将合并到现有配置，不会覆盖已有的 token</span>' +
                '</div>';
            $('#jsfw-import-area').html(html).show();
        },

        hideImport: function () {
            $('#jsfw-import-area').hide();
        },

        doImport: function () {
            var data = $('#jsfw-import-data').val().trim();
            if (!data) { layer.msg('请输入配置数据', { icon: 0 }); return; }
            var self = this;
            layer.confirm(
                '确定导入配置？将会合并到现有站点配置中。',
                { title: '导入配置', icon: 3, btn: ['确认导入', '取消'] },
                function (layerIndex) {
                    layer.close(layerIndex);
                    requestPlugin('xcy_safe', 'import_config', { data: data }, function (rdata) {
                        layer.msg(rdata.msg || (rdata.status ? '导入成功' : '导入失败'), { icon: rdata.status ? 1 : 2 });
                        if (rdata.status) { self.hideImport(); self.getSites(); }
                    });
                }
            );
        },

        /* ======== 挑战日志 ======== */
        getChallengeLogs: function (p) {
            if (p === undefined) p = 1;
            var self = this;
            requestPlugin('xcy_safe', 'get_challenge_logs', { p: p, rows: 15, callback: 'bt_js_challenge.getChallengeLogs' }, function (rdata) {
                if (!rdata.status) {
                    layer.msg(rdata.msg || '读取挑战日志失败', { icon: 2 });
                    return;
                }
                var rows = '';
                for (var i = 0; i < rdata.data.length; i++) {
                    var item = rdata.data[i];
                    var statusClass = item.status === '通过' ? 'jsfw-pill ok' : 'jsfw-pill warn';
                    rows += '<tr>' +
                        '<td width="170">' + htmlEscape(item.time || '') + '</td>' +
                        '<td width="130">' + htmlEscape(item.ip || '') + '</td>' +
                        '<td width="160">' + htmlEscape(item.site || '') + '</td>' +
                        '<td width="140">' + htmlEscape(item.type || '') + '</td>' +
                        '<td width="80"><span class="' + statusClass + '">' + htmlEscape(item.status || '') + '</span></td>' +
                        '<td width="70">' + htmlEscape(item.count || 1) + '</td>' +
                        '<td><span class="jsfw-log-detail" title="' + htmlEscape(item.ua || '') + '">' + htmlEscape(item.ua || '') + '</span></td>' +
                    '</tr>';
                }
                if (!rows) rows = '<tr><td colspan="7" class="text-center">暂无挑战日志</td></tr>';

                var body =
                    '<div class="jsfw-topbar">' +
                        '<div class="jsfw-heading"><h3 class="jsfw-title">挑战日志</h3><div class="jsfw-subtitle">共 ' + (rdata.count || 0) + ' 条记录</div></div>' +
                        '<div class="jsfw-actions">' +
                            '<button class="btn btn-default btn-sm" onclick="bt_js_challenge.getChallengeLogs()">刷新</button>' +
                            '<button class="btn btn-danger btn-sm" onclick="bt_js_challenge.clearChallengeLogs()">清理挑战日志</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="jsfw-log-wrap"><table class="table table-hover">' +
                        '<thead><tr><th width="170">时间</th><th width="130">IP</th><th width="160">域名</th><th width="140">类型</th><th width="80">状态</th><th width="70">次数</th><th>UA</th></tr></thead>' +
                        '<tbody>' + rows + '</tbody>' +
                    '</table></div>' +
                    '<div class="page" style="margin-top:15px">' + (rdata.page || '') + '</div>';
                $('.plugin_body').html(body);
            });
        },

        clearChallengeLogs: function () {
            var self = this;
            layer.confirm('确定清理所有挑战日志？此操作不可恢复！', { title: '清理挑战日志', icon: 3, btn: ['确定清理', '取消'] }, function (index) {
                layer.close(index);
                requestPlugin('xcy_safe', 'clear_challenge_logs', {}, function (rdata) {
                    layer.msg(rdata.msg || (rdata.status ? '挑战日志已清理' : '清理失败'), { icon: rdata.status ? 1 : 2 });
                    self.getChallengeLogs();
                });
            });
        },

        /* ======== 操作日志 ======== */
        getLogs: function (p) {
            if (p === undefined) p = 1;
            var self = this;
            requestPlugin('xcy_safe', 'get_logs', { p: p, rows: 12, callback: 'bt_js_challenge.getLogs' }, function (rdata) {
                if (!rdata.status) {
                    layer.msg(rdata.msg || '读取日志失败', { icon: 2 });
                    return;
                }
                var rows = '';
                for (var i = 0; i < rdata.data.length; i++) {
                    var item = rdata.data[i];
                    rows += '<tr>' +
                        '<td width="160">' + htmlEscape(item.time || '') + '</td>' +
                        '<td width="80">' + htmlEscape(item.action || '') + '</td>' +
                        '<td width="180">' + htmlEscape(item.site || '') + '</td>' +
                        '<td><span class="jsfw-log-detail" title="' + htmlEscape(item.detail || '') + '">' + htmlEscape(item.detail || '') + '</span></td>' +
                    '</tr>';
                }
                if (!rows) rows = '<tr><td colspan="4" class="text-center">暂无日志</td></tr>';

                var body =
                    '<div class="jsfw-topbar">' +
                        '<div class="jsfw-heading"><h3 class="jsfw-title">操作日志</h3><div class="jsfw-subtitle">共 ' + (rdata.count || 0) + ' 条记录</div></div>' +
                        '<div class="jsfw-actions">' +
                            '<button class="btn btn-default btn-sm" onclick="bt_js_challenge.getLogs()">刷新</button>' +
                            '<button class="btn btn-danger btn-sm" onclick="bt_js_challenge.clearLogs()">清理日志</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="jsfw-log-wrap"><table class="table table-hover">' +
                        '<thead><tr><th width="160">时间</th><th width="80">操作</th><th width="180">网站</th><th>详情</th></tr></thead>' +
                        '<tbody>' + rows + '</tbody>' +
                    '</table></div>' +
                    '<div class="page" style="margin-top:15px">' + (rdata.page || '') + '</div>';
                $('.plugin_body').html(body);
            });
        },

        clearLogs: function () {
            var self = this;
            layer.confirm('确定清理所有插件操作日志？此操作不可恢复！', { title: '清理日志', icon: 3, btn: ['确定清理', '取消'] }, function (index) {
                layer.close(index);
                requestPlugin('xcy_safe', 'clear_logs', {}, function (rdata) {
                    layer.msg(rdata.msg || (rdata.status ? '日志已清理' : '清理失败'), { icon: rdata.status ? 1 : 2 });
                    self.getLogs();
                });
            });
        }
    };

    /* ---- 初始化 ---- */
    $(function () {
        $('.layui-layer-page').css({ 'width': '1180px' });
        $('.bt-w-menu p').click(function () {
            $(this).addClass('bgw').siblings().removeClass('bgw');
        });
        bt_js_challenge.getSites();
    });

})();