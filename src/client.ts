/**
 * ClawFi API Client
 * Works with ClawFi API or falls back to Dexscreener for market data
 */

import { ClawFiConfig, Signal, TokenAnalysis, ApiResponse, ChainId, MarketData, TokenData } from './types';

const DEFAULT_CONFIG: Required<ClawFiConfig> = {
  apiKey: '',
  baseUrl: 'https://api.clawfi.ai',
  timeout: 30000,
};

const DEXSCREENER_API = 'https://api.dexscreener.com';
const GOPLUS_API = 'https://api.gopluslabs.io/api/v1';

// Chain ID mapping for GoPlus
const CHAIN_IDS: Record<string, string> = {
  ethereum: '1',
  bsc: '56',
  polygon: '137',
  arbitrum: '42161',
  optimism: '10',
  avalanche: '43114',
  fantom: '250',
  base: '8453',
};

/**
 * ClawFi SDK Client
 * 
 * @example
 * ```typescript
 * import { ClawFi } from '@clawfi/sdk';
 * 
 * const clawfi = new ClawFi({ apiKey: 'your-api-key' });
 * 
 * // Get token analysis
 * const analysis = await clawfi.analyzeToken('ethereum', '0x...');
 * 
 * // Get signals
 * const signals = await clawfi.getSignals('ethereum', '0x...');
 * ```
 */
export class ClawFi {
  private config: Required<ClawFiConfig>;
  private useFallback: boolean = false;

  constructor(config: ClawFiConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Make authenticated API request to ClawFi
   */
  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.config.baseUrl}${endpoint}`;
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers: { ...headers, ...options.headers },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const data = await response.json();

      if (!response.ok) {
        // Try fallback on error
        this.useFallback = true;
        return {
          success: false,
          error: data.error || `HTTP ${response.status}`,
          timestamp: Date.now(),
        };
      }

      return {
        success: true,
        data,
        timestamp: Date.now(),
      };
    } catch (error) {
      clearTimeout(timeout);
      this.useFallback = true;
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Fetch from Dexscreener API (fallback)
   */
  private async fetchDexscreener(address: string): Promise<any> {
    const response = await fetch(`${DEXSCREENER_API}/latest/dex/tokens/${address}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.pairs?.[0] || null;
  }

  /**
   * Fetch security data from GoPlus (fallback)
   */
  private async fetchGoPlus(chain: ChainId, address: string): Promise<any> {
    const chainId = CHAIN_IDS[chain];
    if (!chainId) return null;
    
    try {
      const response = await fetch(
        `${GOPLUS_API}/token_security/${chainId}?contract_addresses=${address}`
      );
      const data = await response.json();
      return data.result?.[address.toLowerCase()] || null;
    } catch {
      return null;
    }
  }

  /**
   * Generate signals from GoPlus data
   */
  private generateSignalsFromGoPlus(goPlusData: any): Signal[] {
    const signals: Signal[] = [];
    
    if (!goPlusData) return signals;

    if (goPlusData.is_honeypot === '1') {
      signals.push({
        id: `sig_honeypot_${Date.now()}`,
        type: 'honeypot',
        severity: 'critical',
        title: 'Honeypot Detected',
        summary: 'This token cannot be sold - likely a scam',
        timestamp: Date.now(),
      });
    }

    if (goPlusData.is_mintable === '1') {
      signals.push({
        id: `sig_mintable_${Date.now()}`,
        type: 'contract_risk',
        severity: 'high',
        title: 'Mintable Token',
        summary: 'Token supply can be increased by owner',
        timestamp: Date.now(),
      });
    }

    if (goPlusData.hidden_owner === '1') {
      signals.push({
        id: `sig_hidden_${Date.now()}`,
        type: 'contract_risk',
        severity: 'high',
        title: 'Hidden Owner',
        summary: 'Contract has hidden owner functions',
        timestamp: Date.now(),
      });
    }

    if (goPlusData.is_open_source !== '1') {
      signals.push({
        id: `sig_unverified_${Date.now()}`,
        type: 'contract_risk',
        severity: 'medium',
        title: 'Unverified Contract',
        summary: 'Contract source code is not verified',
        timestamp: Date.now(),
      });
    }

    const sellTax = parseFloat(goPlusData.sell_tax || '0') * 100;
    if (sellTax > 10) {
      signals.push({
        id: `sig_tax_${Date.now()}`,
        type: 'contract_risk',
        severity: sellTax > 30 ? 'critical' : 'high',
        title: 'High Sell Tax',
        summary: `Sell tax is ${sellTax.toFixed(1)}%`,
        timestamp: Date.now(),
      });
    }

    if (goPlusData.is_blacklisted === '1') {
      signals.push({
        id: `sig_blacklist_${Date.now()}`,
        type: 'contract_risk',
        severity: 'medium',
        title: 'Blacklist Enabled',
        summary: 'Contract can blacklist addresses',
        timestamp: Date.now(),
      });
    }

    // Holder concentration
    if (goPlusData.holders && Array.isArray(goPlusData.holders)) {
      const top10 = goPlusData.holders.slice(0, 10);
      const top10Percent = top10.reduce((sum: number, h: any) => sum + parseFloat(h.percent || '0'), 0) * 100;
      
      if (top10Percent > 50) {
        signals.push({
          id: `sig_concentration_${Date.now()}`,
          type: 'holder_concentration',
          severity: top10Percent > 70 ? 'high' : 'medium',
          title: 'High Holder Concentration',
          summary: `Top 10 holders control ${top10Percent.toFixed(1)}% of supply`,
          timestamp: Date.now(),
        });
      }
    }

    return signals;
  }

  // ============================================
  // Token Analysis
  // ============================================

  /**
   * Get comprehensive token analysis
   * Falls back to Dexscreener + GoPlus if main API unavailable
   */
  async analyzeToken(chain: ChainId, address: string): Promise<ApiResponse<TokenAnalysis>> {
    // Try main API first
    if (!this.useFallback) {
      const result = await this.request<TokenAnalysis>(`/analyze/${chain}/${address}`);
      if (result.success) return result;
    }

    // Fallback to public APIs
    try {
      const [dexData, goPlusData] = await Promise.all([
        this.fetchDexscreener(address),
        this.fetchGoPlus(chain, address),
      ]);

      if (!dexData) {
        return {
          success: false,
          error: 'Token not found',
          timestamp: Date.now(),
        };
      }

      const signals = this.generateSignalsFromGoPlus(goPlusData);
      const riskScore = this.calculateRiskScore(signals);

      const analysis: TokenAnalysis = {
        token: {
          address,
          chain,
          name: dexData.baseToken?.name,
          symbol: dexData.baseToken?.symbol,
          price: parseFloat(dexData.priceUsd || '0'),
          priceChange24h: dexData.priceChange?.h24 || 0,
          marketCap: dexData.marketCap,
          fdv: dexData.fdv,
          volume24h: dexData.volume?.h24 || 0,
          liquidity: dexData.liquidity?.usd || 0,
        },
        market: {
          price: parseFloat(dexData.priceUsd || '0'),
          priceChange: {
            m5: dexData.priceChange?.m5 || 0,
            h1: dexData.priceChange?.h1 || 0,
            h6: dexData.priceChange?.h6 || 0,
            h24: dexData.priceChange?.h24 || 0,
          },
          volume: {
            m5: dexData.volume?.m5 || 0,
            h1: dexData.volume?.h1 || 0,
            h6: dexData.volume?.h6 || 0,
            h24: dexData.volume?.h24 || 0,
          },
          transactions: {
            buys: dexData.txns?.h24?.buys || 0,
            sells: dexData.txns?.h24?.sells || 0,
          },
          liquidity: dexData.liquidity?.usd || 0,
          marketCap: dexData.marketCap,
          fdv: dexData.fdv,
        },
        contract: goPlusData ? {
          verified: goPlusData.is_open_source === '1',
          renounced: !goPlusData.owner_address || goPlusData.owner_address === '0x0000000000000000000000000000000000000000',
          honeypot: goPlusData.is_honeypot === '1',
          mintable: goPlusData.is_mintable === '1',
          pausable: goPlusData.transfer_pausable === '1',
          blacklist: goPlusData.is_blacklisted === '1',
          taxBuy: parseFloat(goPlusData.buy_tax || '0') * 100,
          taxSell: parseFloat(goPlusData.sell_tax || '0') * 100,
        } : undefined,
        signals,
        riskScore,
        timestamp: Date.now(),
      };

      return {
        success: true,
        data: analysis,
        timestamp: Date.now(),
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Analysis failed',
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Get quick token data
   */
  async getToken(chain: ChainId, address: string): Promise<ApiResponse<TokenData>> {
    const analysis = await this.analyzeToken(chain, address);
    if (!analysis.success || !analysis.data) {
      return { success: false, error: analysis.error, timestamp: Date.now() };
    }
    return { success: true, data: analysis.data.token, timestamp: Date.now() };
  }

  // ============================================
  // Signals
  // ============================================

  /**
   * Get signals for a token
   */
  async getSignals(chain: ChainId, address: string): Promise<ApiResponse<Signal[]>> {
    // Try main API first
    if (!this.useFallback) {
      const result = await this.request<Signal[]>(`/signals/${chain}/${address}`);
      if (result.success) return result;
    }

    // Fallback
    const goPlusData = await this.fetchGoPlus(chain, address);
    const signals = this.generateSignalsFromGoPlus(goPlusData);
    
    return {
      success: true,
      data: signals,
      timestamp: Date.now(),
    };
  }

  /**
   * Get all recent signals
   */
  async getRecentSignals(limit: number = 50): Promise<ApiResponse<Signal[]>> {
    return this.request<Signal[]>(`/signals/recent?limit=${limit}`);
  }

  /**
   * Subscribe to signals (webhook)
   */
  async subscribeSignals(
    webhookUrl: string,
    filters?: { chains?: ChainId[]; severity?: string[] }
  ): Promise<ApiResponse<{ subscriptionId: string }>> {
    return this.request<{ subscriptionId: string }>('/signals/subscribe', {
      method: 'POST',
      body: JSON.stringify({ webhookUrl, filters }),
    });
  }

  // ============================================
  // Market Data
  // ============================================

  /**
   * Get market data for a token
   */
  async getMarketData(chain: ChainId, address: string): Promise<ApiResponse<MarketData>> {
    const analysis = await this.analyzeToken(chain, address);
    if (!analysis.success || !analysis.data) {
      return { success: false, error: analysis.error, timestamp: Date.now() };
    }
    return { success: true, data: analysis.data.market, timestamp: Date.now() };
  }

  /**
   * Get trending tokens from Dexscreener
   */
  async getTrending(chain?: ChainId): Promise<ApiResponse<TokenData[]>> {
    try {
      const response = await fetch(`${DEXSCREENER_API}/token-boosts/top/v1`);
      const data = await response.json();
      
      if (!Array.isArray(data)) {
        return { success: false, error: 'Invalid response', timestamp: Date.now() };
      }

      const tokens: TokenData[] = data
        .filter((t: any) => !chain || t.chainId === chain)
        .slice(0, 20)
        .map((t: any) => ({
          address: t.tokenAddress,
          chain: t.chainId,
        }));

      return { success: true, data: tokens, timestamp: Date.now() };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch trending',
        timestamp: Date.now(),
      };
    }
  }

  // ============================================
  // Security
  // ============================================

  /**
   * Get contract analysis
   */
  async getContractAnalysis(chain: ChainId, address: string): Promise<ApiResponse<TokenAnalysis['contract']>> {
    const analysis = await this.analyzeToken(chain, address);
    if (!analysis.success || !analysis.data) {
      return { success: false, error: analysis.error, timestamp: Date.now() };
    }
    return { success: true, data: analysis.data.contract, timestamp: Date.now() };
  }

  /**
   * Check if token is a honeypot
   */
  async checkHoneypot(chain: ChainId, address: string): Promise<ApiResponse<{ isHoneypot: boolean; reason?: string }>> {
    const goPlusData = await this.fetchGoPlus(chain, address);
    
    const isHoneypot = goPlusData?.is_honeypot === '1' || 
                       goPlusData?.cannot_sell_all === '1' ||
                       (parseFloat(goPlusData?.sell_tax || '0') > 0.5);
    
    let reason: string | undefined;
    if (goPlusData?.is_honeypot === '1') reason = 'Flagged as honeypot';
    else if (goPlusData?.cannot_sell_all === '1') reason = 'Cannot sell all tokens';
    else if (parseFloat(goPlusData?.sell_tax || '0') > 0.5) reason = 'Sell tax over 50%';

    return {
      success: true,
      data: { isHoneypot, reason },
      timestamp: Date.now(),
    };
  }

  // ============================================
  // Watchlist
  // ============================================

  /**
   * Add token to watchlist
   */
  async addToWatchlist(chain: ChainId, address: string): Promise<ApiResponse<{ id: string }>> {
    return this.request<{ id: string }>('/watchlist', {
      method: 'POST',
      body: JSON.stringify({ chain, address }),
    });
  }

  /**
   * Get watchlist
   */
  async getWatchlist(): Promise<ApiResponse<TokenData[]>> {
    return this.request<TokenData[]>('/watchlist');
  }

  /**
   * Remove from watchlist
   */
  async removeFromWatchlist(id: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/watchlist/${id}`, { method: 'DELETE' });
  }

  // ============================================
  // Utilities
  // ============================================

  private calculateRiskScore(signals: Signal[]): number {
    const weights = { info: 0, low: 5, medium: 15, high: 25, critical: 40 };
    const score = signals.reduce((sum, s) => sum + (weights[s.severity] || 0), 0);
    return Math.min(100, score);
  }

  /**
   * Search tokens
   */
  async search(query: string): Promise<ApiResponse<TokenData[]>> {
    try {
      const response = await fetch(`${DEXSCREENER_API}/latest/dex/search?q=${encodeURIComponent(query)}`);
      const data = await response.json();
      
      const tokens: TokenData[] = (data.pairs || []).slice(0, 20).map((p: any) => ({
        address: p.baseToken?.address,
        chain: p.chainId,
        name: p.baseToken?.name,
        symbol: p.baseToken?.symbol,
        price: parseFloat(p.priceUsd || '0'),
        priceChange24h: p.priceChange?.h24 || 0,
        marketCap: p.marketCap,
        volume24h: p.volume?.h24 || 0,
        liquidity: p.liquidity?.usd || 0,
      }));

      return { success: true, data: tokens, timestamp: Date.now() };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Search failed',
        timestamp: Date.now(),
      };
    }
  }
}

export default ClawFi;
