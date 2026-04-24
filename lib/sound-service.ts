/**
 * Sound Alert Service
 * Plays audio alerts for notifications
 */

export type SoundType = 'ping' | 'siren';

class SoundService {
  private audioContext: AudioContext | null = null;
  private isMuted = false;

  constructor() {
    this.isMuted = this.loadMuteState();
  }

  /**
   * Load mute state from localStorage
   */
  private loadMuteState(): boolean {
    if (typeof window === 'undefined') return false;
    return localStorage.getItem('soundAlertsMuted') === 'true';
  }

  /**
   * Save mute state to localStorage
   */
  private saveMuteState(muted: boolean) {
    if (typeof window === 'undefined') return;
    localStorage.setItem('soundAlertsMuted', muted.toString());
  }

  /**
   * Initialize AudioContext (needed for web audio API)
   */
  private initAudioContext(): AudioContext {
    if (this.audioContext) return this.audioContext;

    if (typeof window === 'undefined' || !window.AudioContext) {
      throw new Error('Web Audio API not supported');
    }

    this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
    return this.audioContext;
  }

  /**
   * Play a ping sound (for info alerts)
   */
  async playPing(): Promise<void> {
    if (this.isMuted) return;

    try {
      const ctx = this.initAudioContext();
      const now = ctx.currentTime;

      // Create oscillator for ping sound
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.connect(gain);
      gain.connect(ctx.destination);

      // Ping parameters: 800Hz, 150ms
      osc.frequency.setValueAtTime(800, now);
      gain.gain.setValueAtTime(0.3, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.15);

      osc.start(now);
      osc.stop(now + 0.15);

      console.log('🔔 Ping sound played');
    } catch (error) {
      console.warn('Failed to play ping sound:', error);
    }
  }

  /**
   * Play a siren sound (for critical alerts)
   */
  async playSiren(): Promise<void> {
    if (this.isMuted) return;

    try {
      const ctx = this.initAudioContext();
      const now = ctx.currentTime;
      const duration = 2; // 2 second siren

      // Create two oscillators for siren effect
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gain = ctx.createGain();

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(ctx.destination);

      // Siren effect: alternate between 1000Hz and 1200Hz
      let time = now;
      const interval = 0.1; // 100ms per beep

      for (let i = 0; i < duration / interval; i++) {
        const freq = i % 2 === 0 ? 1000 : 1200;
        if (i === 0) {
          osc1.frequency.setValueAtTime(freq, now);
        } else {
          osc1.frequency.setValueAtTime(freq, time);
        }
        time += interval;
      }

      gain.gain.setValueAtTime(0.25, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + duration);

      osc1.start(now);
      osc1.stop(now + duration);
      osc2.stop(now + duration);

      console.log('🚨 Siren sound played');
    } catch (error) {
      console.warn('Failed to play siren sound:', error);
    }
  }

  /**
   * Toggle mute state
   */
  toggleMute(): boolean {
    this.isMuted = !this.isMuted;
    this.saveMuteState(this.isMuted);
    return this.isMuted;
  }

  /**
   * Get current mute state
   */
  getMuteState(): boolean {
    return this.isMuted;
  }

  /**
   * Set mute state
   */
  setMute(muted: boolean): void {
    this.isMuted = muted;
    this.saveMuteState(muted);
  }
}

export const soundService = new SoundService();
