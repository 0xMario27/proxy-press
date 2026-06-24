<template>
  <div class="paper">
    <canvas class="magic-particles"></canvas>
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
      <div class="ticker"><span class="ticker-label">LATE EDITION</span> <span class="ticker-text">✦ GIC announces universal proxy standards ✦ Markets surge 2.3% ✦ anyTLS validated by MIT ✦ Stash 3.0 released ✦ ACL4SSR hits 2M users ✦ Owl post delivery now available ✦</span></div>
      <div class="masthead-rule"></div>
    </div>

    <!-- ====== 头条新闻 ====== -->
    <div class="news-light">
    <div class="columns columns-3">
      <div class="col col-span-2">
        <h2 class="headline">Global Internet Consortium Announces Breakthrough in Decentralized Subscription Protocols</h2>
        <div class="moving-photo"><div class="photo-frame"><div class="photo-face"></div><span class="photo-caption">Dr. Helena Vasquez at GIC Summit — <em>Moving Photograph</em></span></div></div>
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
      if (this.form.customBackend) {
        const b = this.form.customBackend;
        if (b.endsWith('?') || b.endsWith('&')) return b;
        return b + (b.includes('?') ? '&' : '?');
      }
      // 剥离已有的 /sub?... 确保由本方法统一拼接
      let base = CONSTANTS.DEFAULT_BACKEND.replace(/\/sub\?.*$/, '');
      const isLocal = base.includes('localhost') || base.includes('127.0.0.1');
      if (isLocal) {
        base = base.replace(/:\d+$/, '');
        return `${base}:25600/sub?mode=${this.providerMode ? 'provider' : 'inline'}&`;
      }
      // 远程后端
      const sep = base.endsWith('/') ? '' : '/';
      return `${base}${sep}sub?mode=${this.providerMode ? 'provider' : 'inline'}&`;
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
    this.$nextTick(() => this.initMagicParticles());
  },
  methods: {
    initMagicParticles() {
      const canvas = this.$el.querySelector('.magic-particles');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const particles = Array.from({length: 15}, () => ({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4 - 0.2,
        life: 1, maxLife: 200 + Math.random() * 300,
        size: 1 + Math.random() * 2
      }));
      const animate = () => {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (const p of particles) {
          p.x += p.vx; p.y += p.vy; p.life--;
          if (p.life <= 0) { p.x = Math.random() * canvas.width; p.y = canvas.height + 10; p.life = p.maxLife; }
          const alpha = Math.min(1, p.life / 50) * 0.4;
          ctx.fillStyle = `rgba(200,170,100,` + alpha + ')';
          ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI*2); ctx.fill();
          if (Math.random() < 0.02) {
            ctx.fillStyle = 'rgba(255,220,140,0.8)';
            ctx.beginPath(); ctx.arc(p.x, p.y, p.size*2, 0, Math.PI*2); ctx.fill();
          }
        }
        requestAnimationFrame(animate);
      };
      animate();
    },
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
          if (c.includes('No nodes were found') || c.includes('Invalid request')) throw Error(c.trim());
          this._saveFile(c);
        })
        .catch(e => {
          this.notify(`Cannot download directly: ${e.message}. Copy URL and open manually.`, 'error');
        })
        .finally(() => { this.downloading = false; });
    },
    _saveFile(content) {
      const b = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = this.downloadFileName;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(a.href);
      this.notify(`Downloaded: ${this.downloadFileName}`, 'success');
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
  max-width: 1020px;
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

.headline { font-family: "Times New Roman", serif; font-size: clamp(18px, 3.5vw, 26px); font-weight: 900; line-height: 1.2; margin: 0 0 6px; }
.subhead { font-family: "Times New Roman", serif; font-size: 14px; font-weight: 900; margin: 8px 0 4px; text-transform: uppercase; letter-spacing: 1px; }
.byline { font-size: 9px; color: #666; font-style: italic; font-family: "Helvetica Neue", Arial, sans-serif; margin-bottom: 6px; }
.dropcap { float: left; font-size: 42px; line-height: 0.8; margin: 0 4px 0 0; font-weight: 900; font-family: "Times New Roman", serif; }
.quote { margin: 8px 16px; padding: 6px 0; border-top: 1px solid #aaa; border-bottom: 1px solid #aaa; font-style: italic; font-size: 13px; text-align: center; color: #333; }
.quote-attrib { font-size: 9px; font-style: normal; color: #666; font-family: "Helvetica Neue", Arial, sans-serif; }
.brief { font-size: 10px; line-height: 1.4; margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px dotted #ccc; }

p { font-size: 14px; line-height: 1.55; margin: 0 0 6px; text-align: justify; }
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
.checks { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; align-items: start; }
.checks >>> .el-checkbox { margin: 0 !important; }

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

/* 全局覆盖 — 报纸风格统一 */
>>> .el-input__inner, >>> .el-textarea__inner {
  border-radius: 0 !important; border: 1px solid #999 !important;
  background: #fff !important; font-family: "Courier New", monospace !important; font-size: 13px;
  color: #1a1a1a !important;
}
>>> .el-input__inner:hover, >>> .el-textarea__inner:hover { border-color: #555 !important; }
>>> .el-input__inner:focus, >>> .el-textarea__inner:focus { border-color: #1a1a1a !important; box-shadow: none !important; }

/* 下拉选择器触发框 */
>>> .el-select .el-input__inner {
  background: #fff !important;
}
>>> .el-select .el-input__suffix {
  color: #555 !important;
  display: flex !important; align-items: center !important;
}
>>> .el-select .el-input__suffix-inner {
  display: flex !important; align-items: center !important; justify-content: center !important;
}
>>> .el-select .el-input .el-select__caret {
  color: #555 !important; font-size: 14px !important; line-height: 1 !important;
  transition: transform 0.2s ease;
  display: flex !important; align-items: center !important;
}
>>> .el-select .el-input.is-focus .el-select__caret { transform: rotate(180deg); color: #1a1a1a !important; }
>>> .el-select .el-input__icon { color: #555 !important; line-height: 1 !important; }

/* 下拉面板 — 选项文字统一 */
>>> .el-select-dropdown {
  border: 1px solid #1a1a1a !important; border-radius: 0 !important;
  background: #fefdf8 !important;
  box-shadow: 3px 3px 0 rgba(0,0,0,0.12) !important;
}
>>> .el-select-dropdown__item {
  font-family: "Courier New", monospace !important; font-size: 12px !important;
  color: #333 !important; padding: 7px 12px !important;
  border-bottom: 1px dotted #e0ddd5;
  font-weight: normal !important;
}
>>> .el-select-dropdown__item:last-child { border-bottom: none; }
>>> .el-select-dropdown__item:hover {
  background: #f5f0e8 !important; color: #1a1a1a !important;
}
>>> .el-select-dropdown__item.is-selected, >>> .el-select-dropdown__item.selected {
  background: #1a1a1a !important; color: #f5f0e8 !important; font-weight: bold !important;
}
>>> .el-select-dropdown__item.hover, >>> .el-select-dropdown__item.is-hovering {
  background: #f5f0e8 !important;
}
/* 选项分组标题 */
>>> .el-select-group__title {
  font-family: "Helvetica Neue", Arial, sans-serif !important;
  font-size: 9px !important; font-weight: 900 !important;
  letter-spacing: 2px !important; color: #888 !important;
  text-transform: uppercase; padding: 6px 12px 2px !important;
  background: #faf8f3 !important; border-bottom: 1px solid #e0ddd5;
}
/* filterable 搜索框 */
>>> .el-select-dropdown .el-input__inner {
  border-radius: 0 !important; border-color: #ccc !important;
  font-family: "Courier New", monospace !important;
}
/* 去除 popper 默认样式 */
>>> .el-select-dropdown.el-popper {
  padding: 0 !important; border-radius: 0 !important;
  box-shadow: 3px 3px 0 rgba(0,0,0,0.12) !important;
}
>>> .el-popper .popper__arrow, >>> .el-popper .popper__arrow::after {
  display: none !important;
}
>>> .el-select-dropdown__wrap { padding: 0 !important; }
>>> .el-scrollbar__wrap { margin-bottom: 0 !important; overflow-x: hidden !important; }

/* 多选框 */
>>> .el-checkbox.is-bordered {
  border-radius: 0 !important; background: #fff;
  border: 1px solid #ccc !important; padding: 6px 10px !important;
}
>>> .el-checkbox.is-bordered:hover { border-color: #888 !important; background: #faf8f3 !important; }
>>> .el-checkbox.is-checked {
  border-color: #1a1a1a !important; background: #fefdf8 !important;
}
>>> .el-checkbox.is-checked .el-checkbox__label { color: #1a1a1a !important; font-weight: bold; }
>>> .el-checkbox__label { font-size: 12px; font-family: "Courier New", monospace !important; }
>>> .el-checkbox__inner {
  border-radius: 0 !important; border: 1px solid #555 !important;
  background: #fff !important;
}
>>> .el-checkbox__inner:hover { border-color: #1a1a1a !important; }
>>> .el-checkbox.is-checked .el-checkbox__inner {
  background: #1a1a1a !important; border-color: #1a1a1a !important;
}
>>> .el-checkbox__inner::after {
  border-color: #f5f0e8 !important;
  border-width: 2px !important;
}

/* 输入框 placeholder */
>>> .el-input__inner::placeholder, >>> .el-textarea__inner::placeholder {
  color: #bbb !important; font-style: italic; font-family: "Georgia", serif !important;
}

/* 🪄 Harry Potter magic effects */
.magic-particles { position: fixed; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 0; }
.name { animation: inkSpread 3s ease-out, shimmer 4s ease-in-out 3s infinite; }
@keyframes inkSpread { from { letter-spacing: 15px; opacity: 0; } to { letter-spacing: 3px; opacity: 1; } }
@keyframes shimmer { 0%,100% { text-shadow: 0 0 0 transparent; } 50% { text-shadow: 0 0 10px rgba(180,150,60,0.35); } }
.moving-photo { float: right; width: 130px; margin: 0 0 8px 12px; }
.photo-frame { border: 3px double #555; padding: 3px; background: #f5f0e0; animation: frameGlow 2s ease-in-out infinite; }
@keyframes frameGlow { 0%,100% { box-shadow: 0 0 2px rgba(180,140,60,0.2); } 50% { box-shadow: 0 0 10px rgba(180,140,60,0.5); } }
.photo-face { width: 118px; height: 90px; background: linear-gradient(45deg, #d4c5a0, #c4b590, #d4c5a0, #e0d0b0, #d4c5a0); background-size: 300% 300%; animation: faceShift 3s ease-in-out infinite, facePulse 6s ease-in-out infinite; position: relative; overflow: hidden; }
.photo-face::before {
  content: "";
  width: 3px; height: 3px; position: absolute; top: 50%; left: 50%;
  margin-left: -24px; margin-top: -30px;
  background: transparent; border-radius: 0;
  box-shadow:
    9px 0px 0 0 #1a0a0a,
    12px 0px 0 0 #1a0a0a,
    15px 0px 0 0 #1a0a0a,
    18px 0px 0 0 #1a0a0a,
    21px 0px 0 0 #1a0a0a,
    24px 0px 0 0 #1a0a0a,
    27px 0px 0 0 #1a0a0a,
    30px 0px 0 0 #1a0a0a,
    33px 0px 0 0 #1a0a0a,
    6px 3px 0 0 #1a0a0a,
    9px 3px 0 0 #1a0a0a,
    12px 3px 0 0 #1a0a0a,
    15px 3px 0 0 #1a0a0a,
    18px 3px 0 0 #1a0a0a,
    21px 3px 0 0 #1a0a0a,
    24px 3px 0 0 #1a0a0a,
    27px 3px 0 0 #1a0a0a,
    30px 3px 0 0 #1a0a0a,
    33px 3px 0 0 #1a0a0a,
    36px 3px 0 0 #1a0a0a,
    39px 3px 0 0 #1a0a0a,
    3px 6px 0 0 #1a0a0a,
    6px 6px 0 0 #1a0a0a,
    9px 6px 0 0 #1a0a0a,
    12px 6px 0 0 #2c1810,
    15px 6px 0 0 #2c1810,
    18px 6px 0 0 #1a0a0a,
    21px 6px 0 0 #1a0a0a,
    24px 6px 0 0 #1a0a0a,
    27px 6px 0 0 #1a0a0a,
    30px 6px 0 0 #2c1810,
    33px 6px 0 0 #2c1810,
    36px 6px 0 0 #1a0a0a,
    39px 6px 0 0 #1a0a0a,
    42px 6px 0 0 #1a0a0a,
    0px 9px 0 0 #1a0a0a,
    3px 9px 0 0 #1a0a0a,
    6px 9px 0 0 #2c1810,
    9px 9px 0 0 #2c1810,
    12px 9px 0 0 #f4c4a0,
    15px 9px 0 0 #f4c4a0,
    18px 9px 0 0 #f4c4a0,
    21px 9px 0 0 #f4c4a0,
    24px 9px 0 0 #f4c4a0,
    27px 9px 0 0 #f4c4a0,
    30px 9px 0 0 #f4c4a0,
    33px 9px 0 0 #f4c4a0,
    36px 9px 0 0 #2c1810,
    39px 9px 0 0 #2c1810,
    42px 9px 0 0 #1a0a0a,
    45px 9px 0 0 #1a0a0a,
    0px 12px 0 0 #1a0a0a,
    3px 12px 0 0 #2c1810,
    6px 12px 0 0 #f4c4a0,
    9px 12px 0 0 #f4c4a0,
    12px 12px 0 0 #f4c4a0,
    15px 12px 0 0 #f4c4a0,
    18px 12px 0 0 #ffd700,
    21px 12px 0 0 #ffd700,
    24px 12px 0 0 #ffd700,
    27px 12px 0 0 #f4c4a0,
    30px 12px 0 0 #f4c4a0,
    33px 12px 0 0 #f4c4a0,
    36px 12px 0 0 #f4c4a0,
    39px 12px 0 0 #f4c4a0,
    42px 12px 0 0 #2c1810,
    45px 12px 0 0 #1a0a0a,
    0px 15px 0 0 #2c1810,
    3px 15px 0 0 #f4c4a0,
    6px 15px 0 0 #f4c4a0,
    9px 15px 0 0 #f4c4a0,
    12px 15px 0 0 #111,
    15px 15px 0 0 #111,
    18px 15px 0 0 #f4c4a0,
    21px 15px 0 0 #f4c4a0,
    24px 15px 0 0 #f4c4a0,
    27px 15px 0 0 #111,
    30px 15px 0 0 #111,
    33px 15px 0 0 #f4c4a0,
    36px 15px 0 0 #f4c4a0,
    39px 15px 0 0 #f4c4a0,
    42px 15px 0 0 #f4c4a0,
    45px 15px 0 0 #2c1810,
    0px 18px 0 0 #f4c4a0,
    3px 18px 0 0 #f4c4a0,
    6px 18px 0 0 #f4c4a0,
    9px 18px 0 0 #111,
    12px 18px 0 0 #2a8a2a,
    15px 18px 0 0 #fff,
    18px 18px 0 0 #111,
    21px 18px 0 0 #f4c4a0,
    24px 18px 0 0 #111,
    27px 18px 0 0 #fff,
    30px 18px 0 0 #2a8a2a,
    33px 18px 0 0 #111,
    36px 18px 0 0 #f4c4a0,
    39px 18px 0 0 #f4c4a0,
    42px 18px 0 0 #f4c4a0,
    45px 18px 0 0 #f4c4a0,
    0px 21px 0 0 #f4c4a0,
    3px 21px 0 0 #f4c4a0,
    6px 21px 0 0 #f4c4a0,
    9px 21px 0 0 #111,
    12px 21px 0 0 #fff,
    15px 21px 0 0 #2a8a2a,
    18px 21px 0 0 #111,
    21px 21px 0 0 #c4957a,
    24px 21px 0 0 #111,
    27px 21px 0 0 #2a8a2a,
    30px 21px 0 0 #fff,
    33px 21px 0 0 #111,
    36px 21px 0 0 #f4c4a0,
    39px 21px 0 0 #f4c4a0,
    42px 21px 0 0 #f4c4a0,
    45px 21px 0 0 #f4c4a0,
    0px 24px 0 0 #f4c4a0,
    3px 24px 0 0 #f4c4a0,
    6px 24px 0 0 #f4c4a0,
    9px 24px 0 0 #f4c4a0,
    12px 24px 0 0 #111,
    15px 24px 0 0 #111,
    18px 24px 0 0 #f4c4a0,
    21px 24px 0 0 #f4c4a0,
    24px 24px 0 0 #f4c4a0,
    27px 24px 0 0 #111,
    30px 24px 0 0 #111,
    33px 24px 0 0 #f4c4a0,
    36px 24px 0 0 #f4c4a0,
    39px 24px 0 0 #f4c4a0,
    42px 24px 0 0 #f4c4a0,
    45px 24px 0 0 #f4c4a0,
    0px 27px 0 0 #f4c4a0,
    3px 27px 0 0 #f4c4a0,
    6px 27px 0 0 #f4c4a0,
    9px 27px 0 0 #f4c4a0,
    12px 27px 0 0 #f4c4a0,
    15px 27px 0 0 #f4c4a0,
    18px 27px 0 0 #d4956a,
    21px 27px 0 0 #d4956a,
    24px 27px 0 0 #d4956a,
    27px 27px 0 0 #f4c4a0,
    30px 27px 0 0 #f4c4a0,
    33px 27px 0 0 #f4c4a0,
    36px 27px 0 0 #f4c4a0,
    39px 27px 0 0 #f4c4a0,
    42px 27px 0 0 #f4c4a0,
    45px 27px 0 0 #f4c4a0,
    0px 30px 0 0 #f4c4a0,
    3px 30px 0 0 #d4a080,
    6px 30px 0 0 #8b0000,
    9px 30px 0 0 #8b0000,
    12px 30px 0 0 #8b0000,
    15px 30px 0 0 #8b0000,
    18px 30px 0 0 #8b0000,
    21px 30px 0 0 #8b0000,
    24px 30px 0 0 #8b0000,
    27px 30px 0 0 #8b0000,
    30px 30px 0 0 #8b0000,
    33px 30px 0 0 #8b0000,
    36px 30px 0 0 #8b0000,
    39px 30px 0 0 #8b0000,
    42px 30px 0 0 #d4a080,
    45px 30px 0 0 #f4c4a0,
    0px 33px 0 0 #d4a080,
    3px 33px 0 0 #8b0000,
    6px 33px 0 0 #daa520,
    9px 33px 0 0 #8b0000,
    12px 33px 0 0 #daa520,
    15px 33px 0 0 #8b0000,
    18px 33px 0 0 #daa520,
    21px 33px 0 0 #8b0000,
    24px 33px 0 0 #daa520,
    27px 33px 0 0 #8b0000,
    30px 33px 0 0 #daa520,
    33px 33px 0 0 #8b0000,
    36px 33px 0 0 #daa520,
    39px 33px 0 0 #8b0000,
    42px 33px 0 0 #8b0000,
    45px 33px 0 0 #d4a080,
    0px 36px 0 0 #8b0000,
    3px 36px 0 0 #8b0000,
    6px 36px 0 0 #8b0000,
    9px 36px 0 0 #8b0000,
    12px 36px 0 0 #8b0000,
    15px 36px 0 0 #8b0000,
    18px 36px 0 0 #8b0000,
    21px 36px 0 0 #8b0000,
    24px 36px 0 0 #8b0000,
    27px 36px 0 0 #8b0000,
    30px 36px 0 0 #8b0000,
    33px 36px 0 0 #8b0000,
    36px 36px 0 0 #8b0000,
    39px 36px 0 0 #8b0000,
    42px 36px 0 0 #8b0000,
    45px 36px 0 0 #8b0000,
    0px 39px 0 0 #8b0000,
    3px 39px 0 0 #daa520,
    6px 39px 0 0 #8b0000,
    9px 39px 0 0 #daa520,
    12px 39px 0 0 #8b0000,
    15px 39px 0 0 #daa520,
    18px 39px 0 0 #8b0000,
    21px 39px 0 0 #daa520,
    24px 39px 0 0 #8b0000,
    27px 39px 0 0 #daa520,
    30px 39px 0 0 #8b0000,
    33px 39px 0 0 #daa520,
    36px 39px 0 0 #8b0000,
    39px 39px 0 0 #daa520,
    42px 39px 0 0 #8b0000,
    45px 39px 0 0 #daa520,
    0px 42px 0 0 #1a1a2e,
    3px 42px 0 0 #1a1a2e,
    6px 42px 0 0 #1a1a2e,
    9px 42px 0 0 #1a1a2e,
    12px 42px 0 0 #1a1a2e,
    15px 42px 0 0 #1a1a2e,
    18px 42px 0 0 #1a1a2e,
    21px 42px 0 0 #1a1a2e,
    24px 42px 0 0 #1a1a2e,
    27px 42px 0 0 #1a1a2e,
    30px 42px 0 0 #1a1a2e,
    33px 42px 0 0 #1a1a2e,
    36px 42px 0 0 #1a1a2e,
    39px 42px 0 0 #1a1a2e,
    42px 42px 0 0 #1a1a2e,
    45px 42px 0 0 #1a1a2e,
    0px 45px 0 0 #1a1a2e,
    3px 45px 0 0 #1a1a2e,
    6px 45px 0 0 #1a1a2e,
    9px 45px 0 0 #1a1a2e,
    12px 45px 0 0 #1a1a2e,
    15px 45px 0 0 #1a1a2e,
    18px 45px 0 0 #1a1a2e,
    21px 45px 0 0 #1a1a2e,
    24px 45px 0 0 #1a1a2e,
    27px 45px 0 0 #1a1a2e,
    30px 45px 0 0 #1a1a2e,
    33px 45px 0 0 #1a1a2e,
    36px 45px 0 0 #1a1a2e,
    39px 45px 0 0 #1a1a2e,
    42px 45px 0 0 #1a1a2e,
    45px 45px 0 0 #1a1a2e,
    0px 48px 0 0 #1a1a2e,
    3px 48px 0 0 #1a1a2e,
    6px 48px 0 0 #1a1a2e,
    9px 48px 0 0 #1a1a2e,
    12px 48px 0 0 #1a1a2e,
    27px 48px 0 0 #1a1a2e,
    30px 48px 0 0 #1a1a2e,
    33px 48px 0 0 #1a1a2e,
    36px 48px 0 0 #1a1a2e,
    39px 48px 0 0 #1a1a2e,
    42px 48px 0 0 #1a1a2e,
    45px 48px 0 0 #1a1a2e,
    0px 51px 0 0 #1a1a2e,
    3px 51px 0 0 #1a1a2e,
    6px 51px 0 0 #1a1a2e,
    33px 51px 0 0 #1a1a2e,
    36px 51px 0 0 #1a1a2e,
    39px 51px 0 0 #1a1a2e,
    42px 51px 0 0 #1a1a2e,
    45px 51px 0 0 #1a1a2e;
  animation: pixelWink 3.5s ease-in-out infinite, faceWink 4s ease-in-out infinite;
}
@keyframes pixelWink {
  0%,46%,54%,100% { box-shadow: 9px 0px 0 0 #1a0a0a,
    12px 0px 0 0 #1a0a0a,
    15px 0px 0 0 #1a0a0a,
    18px 0px 0 0 #1a0a0a,
    21px 0px 0 0 #1a0a0a,
    24px 0px 0 0 #1a0a0a,
    27px 0px 0 0 #1a0a0a,
    30px 0px 0 0 #1a0a0a,
    33px 0px 0 0 #1a0a0a,
    6px 3px 0 0 #1a0a0a,
    9px 3px 0 0 #1a0a0a,
    12px 3px 0 0 #1a0a0a,
    15px 3px 0 0 #1a0a0a,
    18px 3px 0 0 #1a0a0a,
    21px 3px 0 0 #1a0a0a,
    24px 3px 0 0 #1a0a0a,
    27px 3px 0 0 #1a0a0a,
    30px 3px 0 0 #1a0a0a,
    33px 3px 0 0 #1a0a0a,
    36px 3px 0 0 #1a0a0a,
    39px 3px 0 0 #1a0a0a,
    3px 6px 0 0 #1a0a0a,
    6px 6px 0 0 #1a0a0a,
    9px 6px 0 0 #1a0a0a,
    12px 6px 0 0 #2c1810,
    15px 6px 0 0 #2c1810,
    18px 6px 0 0 #1a0a0a,
    21px 6px 0 0 #1a0a0a,
    24px 6px 0 0 #1a0a0a,
    27px 6px 0 0 #1a0a0a,
    30px 6px 0 0 #2c1810,
    33px 6px 0 0 #2c1810,
    36px 6px 0 0 #1a0a0a,
    39px 6px 0 0 #1a0a0a,
    42px 6px 0 0 #1a0a0a,
    0px 9px 0 0 #1a0a0a,
    3px 9px 0 0 #1a0a0a,
    6px 9px 0 0 #2c1810,
    9px 9px 0 0 #2c1810,
    12px 9px 0 0 #f4c4a0,
    15px 9px 0 0 #f4c4a0,
    18px 9px 0 0 #f4c4a0,
    21px 9px 0 0 #f4c4a0,
    24px 9px 0 0 #f4c4a0,
    27px 9px 0 0 #f4c4a0,
    30px 9px 0 0 #f4c4a0,
    33px 9px 0 0 #f4c4a0,
    36px 9px 0 0 #2c1810,
    39px 9px 0 0 #2c1810,
    42px 9px 0 0 #1a0a0a,
    45px 9px 0 0 #1a0a0a,
    0px 12px 0 0 #1a0a0a,
    3px 12px 0 0 #2c1810,
    6px 12px 0 0 #f4c4a0,
    9px 12px 0 0 #f4c4a0,
    12px 12px 0 0 #f4c4a0,
    15px 12px 0 0 #f4c4a0,
    18px 12px 0 0 #ffd700,
    21px 12px 0 0 #ffd700,
    24px 12px 0 0 #ffd700,
    27px 12px 0 0 #f4c4a0,
    30px 12px 0 0 #f4c4a0,
    33px 12px 0 0 #f4c4a0,
    36px 12px 0 0 #f4c4a0,
    39px 12px 0 0 #f4c4a0,
    42px 12px 0 0 #2c1810,
    45px 12px 0 0 #1a0a0a,
    0px 15px 0 0 #2c1810,
    3px 15px 0 0 #f4c4a0,
    6px 15px 0 0 #f4c4a0,
    9px 15px 0 0 #f4c4a0,
    12px 15px 0 0 #111,
    15px 15px 0 0 #111,
    18px 15px 0 0 #f4c4a0,
    21px 15px 0 0 #f4c4a0,
    24px 15px 0 0 #f4c4a0,
    27px 15px 0 0 #111,
    30px 15px 0 0 #111,
    33px 15px 0 0 #f4c4a0,
    36px 15px 0 0 #f4c4a0,
    39px 15px 0 0 #f4c4a0,
    42px 15px 0 0 #f4c4a0,
    45px 15px 0 0 #2c1810,
    0px 18px 0 0 #f4c4a0,
    3px 18px 0 0 #f4c4a0,
    6px 18px 0 0 #f4c4a0,
    9px 18px 0 0 #111,
    12px 18px 0 0 #2a8a2a,
    15px 18px 0 0 #fff,
    18px 18px 0 0 #111,
    21px 18px 0 0 #f4c4a0,
    24px 18px 0 0 #111,
    27px 18px 0 0 #fff,
    30px 18px 0 0 #2a8a2a,
    33px 18px 0 0 #111,
    36px 18px 0 0 #f4c4a0,
    39px 18px 0 0 #f4c4a0,
    42px 18px 0 0 #f4c4a0,
    45px 18px 0 0 #f4c4a0,
    0px 21px 0 0 #f4c4a0,
    3px 21px 0 0 #f4c4a0,
    6px 21px 0 0 #f4c4a0,
    9px 21px 0 0 #111,
    12px 21px 0 0 #fff,
    15px 21px 0 0 #2a8a2a,
    18px 21px 0 0 #111,
    21px 21px 0 0 #c4957a,
    24px 21px 0 0 #111,
    27px 21px 0 0 #2a8a2a,
    30px 21px 0 0 #fff,
    33px 21px 0 0 #111,
    36px 21px 0 0 #f4c4a0,
    39px 21px 0 0 #f4c4a0,
    42px 21px 0 0 #f4c4a0,
    45px 21px 0 0 #f4c4a0,
    0px 24px 0 0 #f4c4a0,
    3px 24px 0 0 #f4c4a0,
    6px 24px 0 0 #f4c4a0,
    9px 24px 0 0 #f4c4a0,
    12px 24px 0 0 #111,
    15px 24px 0 0 #111,
    18px 24px 0 0 #f4c4a0,
    21px 24px 0 0 #f4c4a0,
    24px 24px 0 0 #f4c4a0,
    27px 24px 0 0 #111,
    30px 24px 0 0 #111,
    33px 24px 0 0 #f4c4a0,
    36px 24px 0 0 #f4c4a0,
    39px 24px 0 0 #f4c4a0,
    42px 24px 0 0 #f4c4a0,
    45px 24px 0 0 #f4c4a0,
    0px 27px 0 0 #f4c4a0,
    3px 27px 0 0 #f4c4a0,
    6px 27px 0 0 #f4c4a0,
    9px 27px 0 0 #f4c4a0,
    12px 27px 0 0 #f4c4a0,
    15px 27px 0 0 #f4c4a0,
    18px 27px 0 0 #d4956a,
    21px 27px 0 0 #d4956a,
    24px 27px 0 0 #d4956a,
    27px 27px 0 0 #f4c4a0,
    30px 27px 0 0 #f4c4a0,
    33px 27px 0 0 #f4c4a0,
    36px 27px 0 0 #f4c4a0,
    39px 27px 0 0 #f4c4a0,
    42px 27px 0 0 #f4c4a0,
    45px 27px 0 0 #f4c4a0,
    0px 30px 0 0 #f4c4a0,
    3px 30px 0 0 #d4a080,
    6px 30px 0 0 #8b0000,
    9px 30px 0 0 #8b0000,
    12px 30px 0 0 #8b0000,
    15px 30px 0 0 #8b0000,
    18px 30px 0 0 #8b0000,
    21px 30px 0 0 #8b0000,
    24px 30px 0 0 #8b0000,
    27px 30px 0 0 #8b0000,
    30px 30px 0 0 #8b0000,
    33px 30px 0 0 #8b0000,
    36px 30px 0 0 #8b0000,
    39px 30px 0 0 #8b0000,
    42px 30px 0 0 #d4a080,
    45px 30px 0 0 #f4c4a0,
    0px 33px 0 0 #d4a080,
    3px 33px 0 0 #8b0000,
    6px 33px 0 0 #daa520,
    9px 33px 0 0 #8b0000,
    12px 33px 0 0 #daa520,
    15px 33px 0 0 #8b0000,
    18px 33px 0 0 #daa520,
    21px 33px 0 0 #8b0000,
    24px 33px 0 0 #daa520,
    27px 33px 0 0 #8b0000,
    30px 33px 0 0 #daa520,
    33px 33px 0 0 #8b0000,
    36px 33px 0 0 #daa520,
    39px 33px 0 0 #8b0000,
    42px 33px 0 0 #8b0000,
    45px 33px 0 0 #d4a080,
    0px 36px 0 0 #8b0000,
    3px 36px 0 0 #8b0000,
    6px 36px 0 0 #8b0000,
    9px 36px 0 0 #8b0000,
    12px 36px 0 0 #8b0000,
    15px 36px 0 0 #8b0000,
    18px 36px 0 0 #8b0000,
    21px 36px 0 0 #8b0000,
    24px 36px 0 0 #8b0000,
    27px 36px 0 0 #8b0000,
    30px 36px 0 0 #8b0000,
    33px 36px 0 0 #8b0000,
    36px 36px 0 0 #8b0000,
    39px 36px 0 0 #8b0000,
    42px 36px 0 0 #8b0000,
    45px 36px 0 0 #8b0000,
    0px 39px 0 0 #8b0000,
    3px 39px 0 0 #daa520,
    6px 39px 0 0 #8b0000,
    9px 39px 0 0 #daa520,
    12px 39px 0 0 #8b0000,
    15px 39px 0 0 #daa520,
    18px 39px 0 0 #8b0000,
    21px 39px 0 0 #daa520,
    24px 39px 0 0 #8b0000,
    27px 39px 0 0 #daa520,
    30px 39px 0 0 #8b0000,
    33px 39px 0 0 #daa520,
    36px 39px 0 0 #8b0000,
    39px 39px 0 0 #daa520,
    42px 39px 0 0 #8b0000,
    45px 39px 0 0 #daa520,
    0px 42px 0 0 #1a1a2e,
    3px 42px 0 0 #1a1a2e,
    6px 42px 0 0 #1a1a2e,
    9px 42px 0 0 #1a1a2e,
    12px 42px 0 0 #1a1a2e,
    15px 42px 0 0 #1a1a2e,
    18px 42px 0 0 #1a1a2e,
    21px 42px 0 0 #1a1a2e,
    24px 42px 0 0 #1a1a2e,
    27px 42px 0 0 #1a1a2e,
    30px 42px 0 0 #1a1a2e,
    33px 42px 0 0 #1a1a2e,
    36px 42px 0 0 #1a1a2e,
    39px 42px 0 0 #1a1a2e,
    42px 42px 0 0 #1a1a2e,
    45px 42px 0 0 #1a1a2e,
    0px 45px 0 0 #1a1a2e,
    3px 45px 0 0 #1a1a2e,
    6px 45px 0 0 #1a1a2e,
    9px 45px 0 0 #1a1a2e,
    12px 45px 0 0 #1a1a2e,
    15px 45px 0 0 #1a1a2e,
    18px 45px 0 0 #1a1a2e,
    21px 45px 0 0 #1a1a2e,
    24px 45px 0 0 #1a1a2e,
    27px 45px 0 0 #1a1a2e,
    30px 45px 0 0 #1a1a2e,
    33px 45px 0 0 #1a1a2e,
    36px 45px 0 0 #1a1a2e,
    39px 45px 0 0 #1a1a2e,
    42px 45px 0 0 #1a1a2e,
    45px 45px 0 0 #1a1a2e,
    0px 48px 0 0 #1a1a2e,
    3px 48px 0 0 #1a1a2e,
    6px 48px 0 0 #1a1a2e,
    9px 48px 0 0 #1a1a2e,
    12px 48px 0 0 #1a1a2e,
    27px 48px 0 0 #1a1a2e,
    30px 48px 0 0 #1a1a2e,
    33px 48px 0 0 #1a1a2e,
    36px 48px 0 0 #1a1a2e,
    39px 48px 0 0 #1a1a2e,
    42px 48px 0 0 #1a1a2e,
    45px 48px 0 0 #1a1a2e,
    0px 51px 0 0 #1a1a2e,
    3px 51px 0 0 #1a1a2e,
    6px 51px 0 0 #1a1a2e,
    33px 51px 0 0 #1a1a2e,
    36px 51px 0 0 #1a1a2e,
    39px 51px 0 0 #1a1a2e,
    42px 51px 0 0 #1a1a2e,
    45px 51px 0 0 #1a1a2e; }
  47%,53%        { box-shadow: 9px 0px 0 0 #1a0a0a,
    12px 0px 0 0 #1a0a0a,
    15px 0px 0 0 #1a0a0a,
    18px 0px 0 0 #1a0a0a,
    21px 0px 0 0 #1a0a0a,
    24px 0px 0 0 #1a0a0a,
    27px 0px 0 0 #1a0a0a,
    30px 0px 0 0 #1a0a0a,
    33px 0px 0 0 #1a0a0a,
    6px 3px 0 0 #1a0a0a,
    9px 3px 0 0 #1a0a0a,
    12px 3px 0 0 #1a0a0a,
    15px 3px 0 0 #1a0a0a,
    18px 3px 0 0 #1a0a0a,
    21px 3px 0 0 #1a0a0a,
    24px 3px 0 0 #1a0a0a,
    27px 3px 0 0 #1a0a0a,
    30px 3px 0 0 #1a0a0a,
    33px 3px 0 0 #1a0a0a,
    36px 3px 0 0 #1a0a0a,
    39px 3px 0 0 #1a0a0a,
    3px 6px 0 0 #1a0a0a,
    6px 6px 0 0 #1a0a0a,
    9px 6px 0 0 #1a0a0a,
    12px 6px 0 0 #2c1810,
    15px 6px 0 0 #2c1810,
    18px 6px 0 0 #1a0a0a,
    21px 6px 0 0 #1a0a0a,
    24px 6px 0 0 #1a0a0a,
    27px 6px 0 0 #1a0a0a,
    30px 6px 0 0 #2c1810,
    33px 6px 0 0 #2c1810,
    36px 6px 0 0 #1a0a0a,
    39px 6px 0 0 #1a0a0a,
    42px 6px 0 0 #1a0a0a,
    0px 9px 0 0 #1a0a0a,
    3px 9px 0 0 #1a0a0a,
    6px 9px 0 0 #2c1810,
    9px 9px 0 0 #2c1810,
    12px 9px 0 0 #f4c4a0,
    15px 9px 0 0 #f4c4a0,
    18px 9px 0 0 #f4c4a0,
    21px 9px 0 0 #f4c4a0,
    24px 9px 0 0 #f4c4a0,
    27px 9px 0 0 #f4c4a0,
    30px 9px 0 0 #f4c4a0,
    33px 9px 0 0 #f4c4a0,
    36px 9px 0 0 #2c1810,
    39px 9px 0 0 #2c1810,
    42px 9px 0 0 #1a0a0a,
    45px 9px 0 0 #1a0a0a,
    0px 12px 0 0 #1a0a0a,
    3px 12px 0 0 #2c1810,
    6px 12px 0 0 #f4c4a0,
    9px 12px 0 0 #f4c4a0,
    12px 12px 0 0 #f4c4a0,
    15px 12px 0 0 #f4c4a0,
    18px 12px 0 0 #ffd700,
    21px 12px 0 0 #ffd700,
    24px 12px 0 0 #ffd700,
    27px 12px 0 0 #f4c4a0,
    30px 12px 0 0 #f4c4a0,
    33px 12px 0 0 #f4c4a0,
    36px 12px 0 0 #f4c4a0,
    39px 12px 0 0 #f4c4a0,
    42px 12px 0 0 #2c1810,
    45px 12px 0 0 #1a0a0a,
    0px 15px 0 0 #2c1810,
    3px 15px 0 0 #f4c4a0,
    6px 15px 0 0 #f4c4a0,
    9px 15px 0 0 #f4c4a0,
    12px 15px 0 0 #111,
    15px 15px 0 0 #111,
    18px 15px 0 0 #f4c4a0,
    21px 15px 0 0 #f4c4a0,
    24px 15px 0 0 #f4c4a0,
    27px 15px 0 0 #111,
    30px 15px 0 0 #111,
    33px 15px 0 0 #f4c4a0,
    36px 15px 0 0 #f4c4a0,
    39px 15px 0 0 #f4c4a0,
    42px 15px 0 0 #f4c4a0,
    45px 15px 0 0 #2c1810,
    0px 18px 0 0 #f4c4a0,
    3px 18px 0 0 #f4c4a0,
    6px 18px 0 0 #f4c4a0,
    9px 18px 0 0 #111,
    12px 18px 0 0 #f4c4a0,
    15px 18px 0 0 #f4c4a0,
    18px 18px 0 0 #111,
    21px 18px 0 0 #f4c4a0,
    24px 18px 0 0 #111,
    27px 18px 0 0 #fff,
    30px 18px 0 0 #2a8a2a,
    33px 18px 0 0 #111,
    36px 18px 0 0 #f4c4a0,
    39px 18px 0 0 #f4c4a0,
    42px 18px 0 0 #f4c4a0,
    45px 18px 0 0 #f4c4a0,
    0px 21px 0 0 #f4c4a0,
    3px 21px 0 0 #f4c4a0,
    6px 21px 0 0 #f4c4a0,
    9px 21px 0 0 #f4c4a0,
    12px 21px 0 0 #d4a080,
    15px 21px 0 0 #d4a080,
    18px 21px 0 0 #d4a080,
    21px 21px 0 0 #c4957a,
    24px 21px 0 0 #111,
    27px 21px 0 0 #2a8a2a,
    30px 21px 0 0 #fff,
    33px 21px 0 0 #111,
    36px 21px 0 0 #f4c4a0,
    39px 21px 0 0 #f4c4a0,
    42px 21px 0 0 #f4c4a0,
    45px 21px 0 0 #f4c4a0,
    0px 24px 0 0 #f4c4a0,
    3px 24px 0 0 #f4c4a0,
    6px 24px 0 0 #f4c4a0,
    9px 24px 0 0 #f4c4a0,
    12px 24px 0 0 #111,
    15px 24px 0 0 #111,
    18px 24px 0 0 #f4c4a0,
    21px 24px 0 0 #f4c4a0,
    24px 24px 0 0 #f4c4a0,
    27px 24px 0 0 #111,
    30px 24px 0 0 #111,
    33px 24px 0 0 #f4c4a0,
    36px 24px 0 0 #f4c4a0,
    39px 24px 0 0 #f4c4a0,
    42px 24px 0 0 #f4c4a0,
    45px 24px 0 0 #f4c4a0,
    0px 27px 0 0 #f4c4a0,
    3px 27px 0 0 #f4c4a0,
    6px 27px 0 0 #f4c4a0,
    9px 27px 0 0 #f4c4a0,
    12px 27px 0 0 #f4c4a0,
    15px 27px 0 0 #f4c4a0,
    18px 27px 0 0 #d4956a,
    21px 27px 0 0 #d4956a,
    24px 27px 0 0 #d4956a,
    27px 27px 0 0 #f4c4a0,
    30px 27px 0 0 #f4c4a0,
    33px 27px 0 0 #f4c4a0,
    36px 27px 0 0 #f4c4a0,
    39px 27px 0 0 #f4c4a0,
    42px 27px 0 0 #f4c4a0,
    45px 27px 0 0 #f4c4a0,
    0px 30px 0 0 #f4c4a0,
    3px 30px 0 0 #d4a080,
    6px 30px 0 0 #8b0000,
    9px 30px 0 0 #8b0000,
    12px 30px 0 0 #8b0000,
    15px 30px 0 0 #8b0000,
    18px 30px 0 0 #8b0000,
    21px 30px 0 0 #8b0000,
    24px 30px 0 0 #8b0000,
    27px 30px 0 0 #8b0000,
    30px 30px 0 0 #8b0000,
    33px 30px 0 0 #8b0000,
    36px 30px 0 0 #8b0000,
    39px 30px 0 0 #8b0000,
    42px 30px 0 0 #d4a080,
    45px 30px 0 0 #f4c4a0,
    0px 33px 0 0 #d4a080,
    3px 33px 0 0 #8b0000,
    6px 33px 0 0 #daa520,
    9px 33px 0 0 #8b0000,
    12px 33px 0 0 #daa520,
    15px 33px 0 0 #8b0000,
    18px 33px 0 0 #daa520,
    21px 33px 0 0 #8b0000,
    24px 33px 0 0 #daa520,
    27px 33px 0 0 #8b0000,
    30px 33px 0 0 #daa520,
    33px 33px 0 0 #8b0000,
    36px 33px 0 0 #daa520,
    39px 33px 0 0 #8b0000,
    42px 33px 0 0 #8b0000,
    45px 33px 0 0 #d4a080,
    0px 36px 0 0 #8b0000,
    3px 36px 0 0 #8b0000,
    6px 36px 0 0 #8b0000,
    9px 36px 0 0 #8b0000,
    12px 36px 0 0 #8b0000,
    15px 36px 0 0 #8b0000,
    18px 36px 0 0 #8b0000,
    21px 36px 0 0 #8b0000,
    24px 36px 0 0 #8b0000,
    27px 36px 0 0 #8b0000,
    30px 36px 0 0 #8b0000,
    33px 36px 0 0 #8b0000,
    36px 36px 0 0 #8b0000,
    39px 36px 0 0 #8b0000,
    42px 36px 0 0 #8b0000,
    45px 36px 0 0 #8b0000,
    0px 39px 0 0 #8b0000,
    3px 39px 0 0 #daa520,
    6px 39px 0 0 #8b0000,
    9px 39px 0 0 #daa520,
    12px 39px 0 0 #8b0000,
    15px 39px 0 0 #daa520,
    18px 39px 0 0 #8b0000,
    21px 39px 0 0 #daa520,
    24px 39px 0 0 #8b0000,
    27px 39px 0 0 #daa520,
    30px 39px 0 0 #8b0000,
    33px 39px 0 0 #daa520,
    36px 39px 0 0 #8b0000,
    39px 39px 0 0 #daa520,
    42px 39px 0 0 #8b0000,
    45px 39px 0 0 #daa520,
    0px 42px 0 0 #1a1a2e,
    3px 42px 0 0 #1a1a2e,
    6px 42px 0 0 #1a1a2e,
    9px 42px 0 0 #1a1a2e,
    12px 42px 0 0 #1a1a2e,
    15px 42px 0 0 #1a1a2e,
    18px 42px 0 0 #1a1a2e,
    21px 42px 0 0 #1a1a2e,
    24px 42px 0 0 #1a1a2e,
    27px 42px 0 0 #1a1a2e,
    30px 42px 0 0 #1a1a2e,
    33px 42px 0 0 #1a1a2e,
    36px 42px 0 0 #1a1a2e,
    39px 42px 0 0 #1a1a2e,
    42px 42px 0 0 #1a1a2e,
    45px 42px 0 0 #1a1a2e,
    0px 45px 0 0 #1a1a2e,
    3px 45px 0 0 #1a1a2e,
    6px 45px 0 0 #1a1a2e,
    9px 45px 0 0 #1a1a2e,
    12px 45px 0 0 #1a1a2e,
    15px 45px 0 0 #1a1a2e,
    18px 45px 0 0 #1a1a2e,
    21px 45px 0 0 #1a1a2e,
    24px 45px 0 0 #1a1a2e,
    27px 45px 0 0 #1a1a2e,
    30px 45px 0 0 #1a1a2e,
    33px 45px 0 0 #1a1a2e,
    36px 45px 0 0 #1a1a2e,
    39px 45px 0 0 #1a1a2e,
    42px 45px 0 0 #1a1a2e,
    45px 45px 0 0 #1a1a2e,
    0px 48px 0 0 #1a1a2e,
    3px 48px 0 0 #1a1a2e,
    6px 48px 0 0 #1a1a2e,
    9px 48px 0 0 #1a1a2e,
    12px 48px 0 0 #1a1a2e,
    27px 48px 0 0 #1a1a2e,
    30px 48px 0 0 #1a1a2e,
    33px 48px 0 0 #1a1a2e,
    36px 48px 0 0 #1a1a2e,
    39px 48px 0 0 #1a1a2e,
    42px 48px 0 0 #1a1a2e,
    45px 48px 0 0 #1a1a2e,
    0px 51px 0 0 #1a1a2e,
    3px 51px 0 0 #1a1a2e,
    6px 51px 0 0 #1a1a2e,
    33px 51px 0 0 #1a1a2e,
    36px 51px 0 0 #1a1a2e,
    39px 51px 0 0 #1a1a2e,
    42px 51px 0 0 #1a1a2e,
    45px 51px 0 0 #1a1a2e; }
}


@keyframes faceShift { 0%,100% { background-position: 0% 50%; } 50% { background-position: 100% 100%; } }
@keyframes facePulse { 0%,100% { filter: brightness(1); } 50% { filter: brightness(1.12); } }
@keyframes faceWink { 0%,100% { transform: scale(1); } 30% { transform: scale(1.08) rotate(-2deg); } 60% { transform: scale(0.94) rotate(1deg); } }
.photo-caption { display: block; font-size: 7px; font-style: italic; text-align: center; color: #888; margin-top: 2px; }
.headline { animation: glowPulse 5s ease-in-out infinite; }
@keyframes glowPulse { 0%,100% { text-shadow: 0 0 0 transparent; } 30% { text-shadow: 0 0 6px rgba(180,150,60,0.2); } }


/* 🪄 ticker - absolute label so text scrolls cleanly behind */
.ticker { background: #1a1a1a; color: #d4c5a0; padding: 0; margin: 4px 0; font-size: 10px; letter-spacing: 1px; overflow: hidden; font-family: "Courier New", monospace; position: relative; height: 24px; line-height: 24px; }
.ticker-label { background: #8b0000; color: #fff; padding: 4px 10px; font-weight: bold; font-size: 9px; white-space: nowrap; position: absolute; left: 0; top: 0; bottom: 0; z-index: 2; display: flex; align-items: center; }
.ticker-text { display: block; animation: tickerScroll 26s linear infinite; white-space: nowrap; padding-left: 100px; line-height: 24px; }
@keyframes tickerScroll { from { transform: translateX(0); } to { transform: translateX(-50%); } }
@media (prefers-reduced-motion) { .ticker-text { animation: none; } }
.mini-ad { border: 1px dashed #999; padding: 8px; text-align: center; font-size: 11px; background: #fdf8ef; margin: 8px 0; }
.mini-ad strong { font-size: 13px; letter-spacing: 1px; }
.ad-stars { font-size: 16px; color: #c4a050; margin-bottom: 2px; letter-spacing: 8px; }
.columns-4 { display: flex; gap: 10px; }
.columns-4 .col { flex: 1; min-width: 0; }
@media (max-width: 700px) { .columns-4 { flex-direction: column; } }

</style>
