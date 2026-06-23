<template>
  <div class="paper">
    <div class="paper-inner">
    <!-- ====== 报头 ====== -->
    <div class="masthead">
      <div class="masthead-top">
        <span class="vol">Vol. I No. 42</span>
        <span class="price">PRICE: FREE</span>
        <span class="date">{{ today }}</span>
      </div>
      <div class="masthead-rule"></div>
      <h1 class="name">THE DAILY CONVERTER</h1>
      <div class="masthead-rule masthead-rule-thick"></div>
      <div class="motto">All the News That Fits Your Proxy — Est. 2026</div>
      <div class="masthead-rule"></div>
    </div>

    <!-- ====== 头条新闻 ====== -->
    <div class="news-light">
    <div class="columns columns-3">
      <div class="col col-span-2">
        <h2 class="headline">Global Internet Consortium Announces Breakthrough in Decentralized Subscription Protocols</h2>
        <div class="byline">By MARCUS T. REEVES &bull; Technology Correspondent</div>
        <p><span class="dropcap">T</span>he Global Internet Consortium (GIC) announced yesterday a landmark agreement to standardize proxy subscription formats across all major platforms. The move, decades in the making, promises to unify the fragmented landscape of node distribution protocols that have long plagued network administrators worldwide.</p>
        <p>"This is a watershed moment for internet freedom," said Dr. Helena Vasquez, chair of the GIC standards committee. "For years, users have struggled with incompatible subscription formats. Now, with the adoption of universal conversion standards, anyone can transform their proxy configurations with a single click."</p>
        <div class="quote">"The barrier between raw subscription data and usable configuration has finally been broken."<br/><span class="quote-attrib">— Dr. Helena Vasquez, GIC Standards Committee</span></div>
        <p>Industry analysts predict widespread adoption within months. Major VPN providers have already pledged support, with several rolling out compatible endpoints by Q3. The protocol supports both legacy inline proxy embedding and modern dynamic provider fetching, giving network operators unprecedented flexibility.</p>
        <p>Critics warn of potential security implications, but proponents argue the benefits far outweigh the risks. "Standardization doesn't mean centralization," Vasquez added. "It means interoperability — and that's the foundation of a free and open internet."</p>
      </div>
      <div class="col">
        <h3 class="subhead">Markets Rally on Tech Optimism</h3>
        <p>Global markets surged Tuesday as investors reacted positively to the GIC announcement. The tech-heavy NASDAQ composite rose 2.3%, led by gains in cloud infrastructure and cybersecurity sectors. "Markets love certainty," noted analyst James Chen of Morgan Stanley. "A unified standard removes uncertainty."</p>
        <div class="rule"></div>
        <h3 class="subhead">Regional Node Deployments Accelerate</h3>
        <p>Data center operators across Southeast Asia report record demand for proxy relay capacity. Singapore, Hong Kong, and Tokyo have seen a 340% increase in anyTLS node deployments since the protocol gained mainstream traction earlier this year. Providers are rushing to expand capacity in emerging markets.</p>
      </div>
    </div>

    <div class="rule rule-thick"></div>

    </div>

    <!-- ====== 订阅转换工具（嵌入为新闻服务） ====== -->
    <h2 class="headline" style="text-align:center; border-top:1px solid #1a1a1a; border-bottom:1px solid #1a1a1a; padding:6px 0;">
      PUBLIC SERVICE: SUBSCRIPTION CONVERTER
    </h2>
    <div class="service-box">
      <p class="service-intro">The Daily Converter provides this free public tool to transform any proxy subscription into a ready-to-use configuration file. Simply paste your link below, select your preferences, and generate.</p>

      <div class="columns columns-2">
        <!-- 左栏：输入 -->
        <div class="col">
          <div class="field">
            <label>SUBSCRIPTION URL</label>
            <el-input v-model="form.sourceSubUrl" type="textarea" :rows="2"
              placeholder="Paste your subscription link here..." @blur="saveSubUrl" />
          </div>
          <div class="field-row">
            <div class="field" style="flex:1">
              <label>CLIENT</label>
              <el-select v-model="form.clientType" style="width:100%">
                <el-option v-for="(v, k) in options.clientTypes" :key="k" :label="k" :value="v" />
              </el-select>
            </div>
            <div class="field" style="flex:1">
              <label>RULESET</label>
              <el-select v-model="form.remoteConfig" allow-create filterable style="width:100%">
                <el-option-group v-for="g in options.remoteConfig" :key="g.label" :label="g.label">
                  <el-option v-for="o in g.options" :key="o.value" :label="o.label" :value="o.value" />
                </el-option-group>
              </el-select>
            </div>
          </div>

          <!-- 模式开关 -->
          <div class="mode-box" @click="providerMode = !providerMode">
            <span class="mode-label">PROXY MODE</span>
            <span class="mode-val" :class="{ active: providerMode }">
              {{ providerMode ? '■ PROVIDER' : '□ INLINE' }}
            </span>
            <span class="mode-note">rules always external</span>
          </div>

          <!-- 高级选项 -->
          <div class="toggle-link" @click="showAdvanced = !showAdvanced">
            {{ showAdvanced ? '▾ Hide advanced options' : '▸ Show advanced options' }}
          </div>
          <div class="options-box" v-if="showAdvanced">
            <div class="options-grid">
              <div class="opt-col">
                <div class="opt-title">SWITCHES</div>
                <div class="checks">
                  <el-checkbox v-model="form.emoji" border size="small">Emoji</el-checkbox>
                  <el-checkbox v-model="form.udp" border size="small" @change="needUdp=true">UDP</el-checkbox>
                  <el-checkbox v-model="form.scv" border size="small">SkipCert</el-checkbox>
                  <el-checkbox v-model="form.sort" border size="small">Sort</el-checkbox>
                  <el-checkbox v-model="form.expand" border size="small">Expand</el-checkbox>
                  <el-checkbox v-model="form.fdn" border size="small">NoBogus</el-checkbox>
                  <el-checkbox v-model="form.insert" border size="small">NetEase</el-checkbox>
                </div>
              </div>
              <div class="opt-col">
                <div class="opt-title">FILTERS &amp; BACKEND</div>
                <el-input v-model="form.includeRemarks" placeholder="Include keywords" size="small" class="opt-in" />
                <el-input v-model="form.excludeRemarks" placeholder="Exclude keywords" size="small" class="opt-in" />
                <el-input v-model="form.filename" placeholder="Output filename" size="small" class="opt-in" />
                <el-input v-model="form.customBackend" placeholder="Custom backend URL" size="small" class="opt-in" />
              </div>
            </div>
          </div>
        </div>

        <!-- 右栏：生成 & 输出 -->
        <div class="col">
          <el-button class="btn-generate" @click="makeUrlClick" :disabled="!canGenerateUrl">
            GENERATE CONFIGURATION
          </el-button>

          <div v-if="customSubUrl" class="output-box">
            <div class="out-url">
              <code>{{ customSubUrl }}</code>
              <el-button size="mini" v-clipboard:copy="customSubUrl" v-clipboard:success="onCopy">COPY</el-button>
            </div>
            <div class="out-actions">
              <el-button size="small" icon="el-icon-download" @click="downloadConfig" :loading="downloading">DOWNLOAD</el-button>
              <el-button size="small" icon="el-icon-connection" @click="clashInstall" :disabled="!canImportClash">IMPORT</el-button>
              <el-button size="small" @click="dialogLoadConfigVisible = true">PARSE URL</el-button>
            </div>
          </div>

          <p class="box-note">Generated configs use rule-provider architecture for optimal performance. All rules fetched externally, keeping your main configuration lightweight and maintainable.</p>
        </div>
      </div>
    </div>

    <div class="rule rule-thick"></div>

    <!-- ====== 下方新闻 ====== -->
    <div class="news-light">
    <div class="columns columns-3">
      <div class="col">
        <h3 class="subhead">Opinion: Why Provider Architecture Matters</h3>
        <div class="byline">By THE EDITORIAL BOARD</div>
        <p>The shift toward provider-based architectures represents more than a technical convenience — it is a philosophical reorientation of how we think about network configuration. Rather than monolithic files containing thousands of hard-coded rules, the provider model embraces modularity, composability, and dynamic updates. This is the architecture the internet deserves.</p>
        <div class="rule"></div>
        <h3 class="subhead">Community Contributors Recognized</h3>
        <p>The ACL4SSR project, now celebrating its fifth year of continuous development, has named its top community contributors for 2026. The volunteer-maintained ruleset database now serves over two million daily active users across 140 countries, making it one of the largest crowd-sourced network configuration projects in history.</p>
      </div>
      <div class="col">
        <h3 class="subhead">Technical Deep Dive: anyTLS Protocol Gains Momentum</h3>
        <p>Security researchers at MIT have published a comprehensive analysis of the anyTLS protocol, confirming its robustness against traffic analysis attacks. The protocol, which wraps proxy connections in standard TLS sessions, has become the de facto standard for modern proxy deployments. "anyTLS represents the best of both worlds — strong encryption with minimal fingerprinting," said lead researcher Dr. Priya Nair.</p>
        <p>The paper, published in the Journal of Network Security, provides the first formal verification of anyTLS's resistance to active probing. This academic validation is expected to accelerate enterprise adoption.</p>
      </div>
      <div class="col">
        <h3 class="subhead">Briefs</h3>
        <div class="brief">CLOUDFLARE announced expanded support for proxy-friendly CDN configurations. &bull; Page 3</div>
        <div class="brief">SINGAPORE data center capacity to double by Q4, driven by regional demand. &bull; Page 5</div>
        <div class="brief">STASH 3.0 released with native proxy-provider support and improved rule-set handling. &bull; Page 8</div>
        <div class="brief">GITHUB reports record contributions to open-source networking projects in 2026. &bull; Page 4</div>
        <div class="brief">NEW ENCRYPTION standard proposed for next-generation proxy protocols. &bull; Page 2</div>
        <div class="rule"></div>
        <h3 class="subhead">Weather</h3>
        <p>Partly cloudy with a chance of proxy. Highs in the mid-70s. Network conditions: stable with occasional latency spikes during peak hours.</p>
        <div class="rule"></div>
        <h3 class="subhead">Corrections</h3>
        <p>In yesterday's edition, the article "Node Deployment Strategies" incorrectly stated that VMess had been deprecated. VMess continues to be supported alongside newer protocols. The Daily Converter regrets the error.</p>
      </div>
    </div>

    </div>

    <!-- 页脚 -->
    <div class="footer">
      <div class="masthead-rule"></div>
      <div class="footer-text">
        THE DAILY CONVERTER &copy; 2026 &bull; Printed on recycled packets &bull; All rights reserved &bull; <span class="version">{{ backendVersion }}</span>
      </div>
    </div>

    <!-- 自定义通知（报纸风格） -->
    <div v-show="notice.show" class="telegram-notice" :class="notice.type">
      <div class="telegram-inner">
        <span class="telegram-label">TELEGRAM</span>
        <span class="telegram-msg">{{ notice.msg }}</span>
        <span class="telegram-close" @click="notice.show = false">✕</span>
      </div>
    </div>

    <!-- dialogs -->
    <ConfigUploadDialog :visible="dialogUploadConfigVisible" :upload-config="uploadConfig" :loading="loading"
      @cancel="dialogUploadConfigVisible = false; uploadConfig = ''" @confirm="handleConfigUpload" />
    <UrlParseDialog :visible="dialogLoadConfigVisible" :load-config="loadConfig" :loading="loading"
      @cancel="dialogLoadConfigVisible = false; loadConfig = ''" @confirm="handleUrlParse" />
      </div>
</div>
</template>

<script>
import { CONSTANTS } from '@/config/constants';
import { CLIENT_TYPES } from '@/config/client-types';
import { REMOTE_CONFIGS } from '@/config/remote-configs';
import { useSubscriptionForm, addCustomParam, saveSubUrl as saveSubscriptionUrl } from '@/composables/useSubscriptionForm';
import { useSubscription } from '@/composables/useSubscription';
import { useUrlParser } from '@/composables/useUrlParser';
import { getLocalStorageItem } from '@/utils/storage';
import { BackendService } from '@/services/backendService';
import ConfigUploadDialog from '@/components/ConfigUploadDialog.vue';
import UrlParseDialog from '@/components/UrlParseDialog.vue';

export default {
  name: 'Subconverter',
  components: { ConfigUploadDialog, UrlParseDialog },
  data() {
    const sf = useSubscriptionForm();
    const d = new Date();
    return {
      today: d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }).toUpperCase(),
      options: { clientTypes: CLIENT_TYPES, backendOptions: [{ value: "http://localhost:25600/sub?" }], remoteConfig: REMOTE_CONFIGS },
      backendVersion: "", loading: false, downloading: false,
      showAdvanced: false, providerMode: true,
      notice: { show: false, msg: '', type: 'info' },
      curtomShortSubUrl: "", dialogUploadConfigVisible: false, loadConfig: "", dialogLoadConfigVisible: false, uploadConfig: "",
      subDocAdvanced: CONSTANTS.DOC_ADVANCED, isPC: true,
      ...sf
    };
  },
  watch: {
    providerMode() { if (this.canGenerateUrl) this.$nextTick(() => this.makeUrlClick()); }
  },
  computed: {
    canGenerateUrl() { return this.form.sourceSubUrl.length > 0 && this.form.clientType; },
    canDownload() { return this.customSubUrl.length > 0 && !this.downloading; },
    canImportClash() { return this.customSubUrl.length > 0; },
    downloadFileName() {
      const c = this.form.clientType || 'clash';
      return `config-${c.replace('&ver=', '-')}.${c.includes('surge') ? 'conf' : 'yaml'}`;
    },
    processedSubUrl() { return this.form.sourceSubUrl.replace(/(\n|\r|\n\r)/g, "|"); },
    advanced() { return this.showAdvanced ? '2' : '1'; },
    currentBackend() {
      if (this.form.customBackend) return this.form.customBackend;
      const base = CONSTANTS.DEFAULT_BACKEND.replace('/sub?', '').replace(/:\d+$/, '');
      // 本地后端 → 加端口和 mode 参数；远程后端 → 直接用
      if (base.includes('localhost') || base.includes('127.0.0.1')) {
        return `${base}:25600/sub?mode=${this.providerMode ? 'provider' : 'inline'}&`;
      }
      return CONSTANTS.DEFAULT_BACKEND;
    }
  },
  created() {
    document.title = "The Daily Converter";
    if (import.meta.env.VITE_USE_STORAGE === 'true') {
      const u = getLocalStorageItem('sourceSubUrl');
      if (u) this.form.sourceSubUrl = u;
    }
  },
  mounted() {
    this.form.clientType = CONSTANTS.DEFAULT_CLIENT_TYPE;
    if (!this.form.remoteConfig) {
      const lc = this.options.remoteConfig[0]?.options[0];
      if (lc) this.form.remoteConfig = lc.value;
    }
    this.getBackendVersion();
  },
  methods: {
    notify(msg, type) {
      this.notice = { show: true, msg, type: type || 'info' };
      clearTimeout(this._noticeTimer);
      this._noticeTimer = setTimeout(() => { this.notice.show = false; }, 2500);
    },
    onCopy() { this.notify('Copied to clipboard', 'success'); },
    clashInstall() {
      if (!this.customSubUrl) return this.notify('Generate URL first', 'error');
      window.open("clash://install-config?url=" + encodeURIComponent(this.customSubUrl));
    },
    makeUrlClick() {
      const url = this.makeUrl(this.form, this.advanced, this.processedSubUrl, this.currentBackend, this.customParams, this.needUdp);
      if (url) { this.customSubUrl = url; this.$copyText(url); this.notify('URL generated & copied', 'success'); }
      else this.notify('Subscription URL and client are required', 'error');
    },
    downloadConfig() {
      this.downloading = true;
      const url = this.makeUrl(this.form, this.advanced, this.processedSubUrl, this.currentBackend, this.customParams, this.needUdp);
      if (!url) { this.downloading = false; this.notify('Subscription URL and client are required', 'error'); return; }
      this.customSubUrl = url;
      fetch(url).then(r => { if (!r.ok) throw Error(`HTTP ${r.status}`); return r.text(); })
        .then(c => {
          const b = new Blob([c], { type: 'text/plain;charset=utf-8' });
          const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = this.downloadFileName;
          document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(a.href);
          this.notify(`Downloaded: ${this.downloadFileName}`, 'success');
        })
        .catch(e => this.notify(`Download failed: ${e.message}`, 'error'))
        .finally(() => { this.downloading = false; });
    },
    handleConfigUpload(configContent) { this.uploadConfig = configContent; this.confirmUploadConfig(); },
    confirmUploadConfig() { this.notify('Upload not configured', 'info'); this.dialogUploadConfigVisible = false; },
    handleUrlParse(url) { this.loadConfig = url; this.confirmLoadConfig(); },
    confirmLoadConfig() {
      this.loading = true;
      this.parseUrl(this.loadConfig, this.form, this.customParams,
        () => { this.dialogLoadConfigVisible = false; this.loadConfig = ""; this.notify('URL parsed', 'success'); },
        e => this.notify(e, 'error')
      ).finally(() => { this.loading = false; });
    },
    backendSearch(q, cb) { cb(this.options.backendOptions.filter(b => b.value.toLowerCase().includes(q.toLowerCase()))); },
    async getBackendVersion() { this.backendVersion = await BackendService.getBackendVersion(this.$axios); },
    saveSubUrl() { saveSubscriptionUrl(this.form); },
    addCustomParam() { addCustomParam(this.customParams); },
    makeShortUrlClick() {},
    goToProject() {}, gotoGayhub() {}, gotoRemoteConfig() {},
    ...useSubscription(),
    ...useUrlParser()
  }
};
</script>

<style scoped>
/* ===== NEWSPAPER STYLE ===== */
* { font-family: Georgia, "Times New Roman", serif; box-sizing: border-box; }

.paper {
  width: 100%;
  min-height: 100vh;
  background: #f5f0e8;
  padding: 16px;
  color: #1a1a1a;
}
.paper-inner {
  max-width: 960px;
  margin: 0 auto;
}
@media (min-width: 900px) {
  .paper { padding: 24px 32px; }
}

/* 报头 */
.masthead { text-align: center; margin-bottom: 12px; }
.masthead-top { display: flex; justify-content: space-between; font-size: 9px; color: #555; letter-spacing: 1px; text-transform: uppercase; font-family: "Helvetica Neue", Arial, sans-serif; margin-bottom: 4px; flex-wrap: wrap; }
.vol, .price, .date { white-space: nowrap; }
.masthead-rule { border-top: 1px solid #1a1a1a; margin: 4px 0; }
.masthead-rule-thick { border-top: 2px solid #1a1a1a; }
.name { font-family: "Times New Roman", serif; font-size: clamp(22px, 5vw, 38px); font-weight: 900; letter-spacing: 2px; text-transform: uppercase; margin: 4px 0; }
.motto { font-size: 10px; color: #555; letter-spacing: 1px; text-transform: uppercase; font-family: "Helvetica Neue", Arial, sans-serif; font-style: italic; }

/* 通用 */
.rule { border-top: 1px solid #aaa; margin: 8px 0; }
.rule-thick { border-top: 2px solid #1a1a1a; }
.columns { display: flex; gap: 16px; margin: 8px 0; }
.columns-2 .col { flex: 1; min-width: 0; }
.columns-3 .col { flex: 1; min-width: 0; }
.col-span-2 { flex: 2 !important; }
@media (max-width: 700px) { .columns { flex-direction: column; } }

.headline { font-family: "Times New Roman", serif; font-size: clamp(16px, 3vw, 22px); font-weight: 900; line-height: 1.2; margin: 0 0 6px; }
.subhead { font-family: "Times New Roman", serif; font-size: 13px; font-weight: 900; margin: 8px 0 4px; text-transform: uppercase; letter-spacing: 1px; }
.byline { font-size: 9px; color: #666; font-style: italic; font-family: "Helvetica Neue", Arial, sans-serif; margin-bottom: 6px; }
.dropcap { float: left; font-size: 42px; line-height: 0.8; margin: 0 4px 0 0; font-weight: 900; font-family: "Times New Roman", serif; }
.quote { margin: 8px 16px; padding: 6px 0; border-top: 1px solid #aaa; border-bottom: 1px solid #aaa; font-style: italic; font-size: 13px; text-align: center; color: #333; }
.quote-attrib { font-size: 9px; font-style: normal; color: #666; font-family: "Helvetica Neue", Arial, sans-serif; }
.brief { font-size: 10px; line-height: 1.4; margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px dotted #ccc; }

p { font-size: 12px; line-height: 1.55; margin: 0 0 6px; text-align: justify; }
.news-light p, .news-light .subhead { color: #777; }
.news-light .headline { color: #555; }
.news-light .byline { color: #aaa; }
.news-light .quote { color: #888; border-color: #ccc; }
.news-light .quote-attrib { color: #aaa; }
.news-light .brief { color: #999; }
.news-light .rule { border-color: #ddd; }

/* 服务区块（突出） */
.service-box {
  border: 3px double #1a1a1a;
  padding: 16px 20px;
  margin: 12px 0;
  background: #fffef9;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  position: relative;
  animation: border-pulse 3s ease-in-out infinite;
}
@keyframes border-pulse {
  0%, 100% { border-color: #1a1a1a; }
  50% { border-color: #888; }
}
.service-intro { font-size: 11px; text-align: center; font-style: italic; margin-bottom: 12px; color: #444; font-weight: 600; }

/* 表单 */
.field { margin-bottom: 8px; }
.field label {
  display: block; font-size: 9px; font-weight: 900; color: #555; letter-spacing: 1px;
  text-transform: uppercase; font-family: "Helvetica Neue", Arial, sans-serif; margin-bottom: 2px;
}
.field-row { display: flex; gap: 8px; }

.mode-box {
  border: 1px solid #aaa; padding: 8px; text-align: center; cursor: pointer; user-select: none;
  margin: 8px 0; background: #fff;
}
.mode-box:hover { background: #faf8f3; }
.mode-label { font-size: 8px; color: #888; letter-spacing: 2px; font-family: "Helvetica Neue", Arial, sans-serif; }
.mode-val { font-size: 15px; font-weight: bold; margin: 0 10px; color: #bbb; }
.mode-val.active { color: #1a1a1a; }
.mode-note { font-size: 8px; color: #aaa; display: block; font-style: italic; }

.toggle-link { font-size: 10px; color: #888; cursor: pointer; margin: 4px 0; font-style: italic; }
.toggle-link:hover { color: #1a1a1a; }

.options-box { border: 1px solid #ddd; padding: 8px; margin: 6px 0; background: #fff; }
.options-grid { display: flex; gap: 12px; }
.opt-col { flex: 1; min-width: 0; }
.opt-title { font-size: 8px; font-weight: 900; color: #888; letter-spacing: 2px; text-transform: uppercase; font-family: "Helvetica Neue", Arial, sans-serif; margin-bottom: 4px; }
/* 打字光标提示 */
.field >>> .el-textarea__inner::placeholder {
  animation: cursor-blink 1.2s step-end infinite;
}
.field >>> .el-textarea__inner:focus::placeholder {
  animation: none;
  opacity: 0.4;
}
@keyframes cursor-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.opt-in { margin-bottom: 4px; }
.checks { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.checks >>> .el-checkbox { margin: 0; }

.btn-generate {
  width: 100%; height: 42px; font-size: 14px; font-weight: 900; letter-spacing: 3px;
  background: #1a1a1a !important; border: none !important; color: #f5f0e8 !important;
  border-radius: 0 !important; margin: 8px 0; text-transform: uppercase;
  font-family: "Times New Roman", serif !important;
  position: relative;
}
.btn-generate:not(.is-disabled)::before {
  content: '➤ ';
  animation: arrow-bounce 0.8s ease-in-out infinite;
  display: inline-block;
}
@keyframes arrow-bounce {
  0%, 100% { transform: translateX(0); }
  50% { transform: translateX(4px); }
}
.btn-generate:hover { background: #333 !important; }
.btn-generate.is-disabled { background: #ccc !important; color: #999 !important; }

.output-box { border: 1px solid #aaa; padding: 8px; margin-top: 8px; background: #fff; }
.out-url { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
.out-url code {
  flex: 1; font-size: 8px; word-break: break-all; color: #555;
  background: #faf8f3; padding: 4px; font-family: "Courier New", monospace;
  border: 1px solid #e0ddd5;
}
.out-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.out-actions .el-button {
  border-radius: 0 !important; border: 1px solid #1a1a1a !important;
  background: #fff !important; color: #1a1a1a !important;
  font-family: "Helvetica Neue", Arial, sans-serif !important; font-size: 10px;
  text-transform: uppercase; letter-spacing: 1px;
}
.out-actions .el-button:hover { background: #1a1a1a !important; color: #fff !important; }
.box-note { font-size: 9px; color: #888; font-style: italic; margin-top: 8px; text-align: center; }

/* 页脚 */
.footer { margin-top: 12px; text-align: center; }
.footer-text { font-size: 8px; color: #888; letter-spacing: 1px; text-transform: uppercase; font-family: "Helvetica Neue", Arial, sans-serif; margin-top: 4px; }
.version { font-family: "Courier New", monospace; }

/* 电报式通知 */
.telegram-notice {
  position: fixed; top: 16px; right: 16px; z-index: 9999;
  background: #fefdf8; border: 2px solid #1a1a1a;
  padding: 0; font-family: "Courier New", monospace;
  box-shadow: 2px 2px 0 rgba(0,0,0,0.15);
  min-width: 260px; max-width: 400px;
  animation: notice-in 0.25s ease-out;
}
@keyframes notice-in {
  from { transform: translateX(60px); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
.telegram-notice.error { border-color: #8b0000; background: #fff5f5; }
.telegram-notice.success { border-color: #1a5c1a; background: #f5fff5; }
.telegram-inner {
  display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px;
}
.telegram-label {
  font-size: 9px; font-weight: 900; letter-spacing: 2px; color: #555;
  text-transform: uppercase; white-space: nowrap;
  border-right: 1px solid #ccc; padding-right: 10px;
}
.telegram-notice.error .telegram-label { color: #8b0000; }
.telegram-notice.success .telegram-label { color: #1a5c1a; }
.telegram-msg { flex: 1; font-size: 12px; color: #333; line-height: 1.4; }
.telegram-close {
  cursor: pointer; font-size: 14px; color: #999; flex-shrink: 0;
  font-family: Georgia, serif;
}
.telegram-close:hover { color: #1a1a1a; }

/* 全局覆盖 */
>>> .el-input__inner, >>> .el-textarea__inner {
  border-radius: 0 !important; border: 1px solid #999 !important;
  background: #fff !important; font-family: "Courier New", monospace !important; font-size: 12px;
}
>>> .el-checkbox.is-bordered { border-radius: 0 !important; background: #fff; border: 1px solid #ccc !important; }
>>> .el-checkbox.is-checked { border-color: #1a1a1a !important; }
>>> .el-checkbox__label { font-size: 11px; }
</style>
