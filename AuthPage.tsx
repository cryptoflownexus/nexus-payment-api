import React, { useState, useEffect } from 'react';
import { X, User, AlertTriangle, Loader2, Unlock, Mail, ArrowRight } from 'lucide-react';
import { useStore } from '../store/useStore';
import { SecurityManager } from '../utils/SecurityManager';
import { SystemConfigStore } from '../engine_v2/store/SystemConfigStore';
import { invoke } from "@tauri-apps/api/core";
import { supabase } from '../utils/supabase';

interface AuthPageProps {
  onClose: () => void;
  onEnter: () => void;
}

export const AuthPage: React.FC<AuthPageProps> = ({ onClose, onEnter }) => {
  const { config, setDecryptedSessionKeys, updateConfig } = useStore((state) => state);
  const isTauri = typeof window !== 'undefined' && !!(window as any).__TAURI_INTERNALS__;

  const defaultVaultType = config?.vaultConfig?.vaultType || 'pin';
  const language = config?.ui?.language || 'EN';
  const theme = config?.ui?.appearance === 'DAY' ? 'light' : 'dark';

  const [authMode, setAuthMode] = useState<'login' | 'signup' | 'unlock'>(config?.encryptedVault ? 'unlock' : 'login');
  const [loginType, setLoginType] = useState<'pin' | 'password'>(defaultVaultType);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    const checkConnectivity = async () => {
      try {
        const start = Date.now();
        const { error: hbError } = await supabase.from('profiles').select('id').limit(1);
        const end = Date.now();
        if (hbError && hbError.code !== 'PGRST116') {
           console.warn("[Auth] Connectivity check returned error:", hbError);
        }
        if (end - start > 5000) {
          console.warn(`[Auth] Slow database connection detected: ${end - start}ms`);
        }
      } catch (e) {
        console.warn("[Auth] Connectivity check failed");
      }
    };
    checkConnectivity();
  }, []);

  const handleSupabaseAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isDecrypting) return;
    setError(null);
    setSuccessMsg(null);
    setIsDecrypting(true);

    try {
      // Simulate timeout for fake domains hanging
      const authPromise = authMode === 'signup' 
        ? supabase.auth.signUp({ email, password })
        : supabase.auth.signInWithPassword({ email, password });
        
      const timeoutPromise = new Promise<{data: any, error: any}>((_, reject) => 
        setTimeout(() => reject(new Error(language === 'ID' 
          ? 'Koneksi ke database timeout (60 detik). Ini bisa disebabkan oleh ISP Anda memblokir koneksi Supabase, status project Supabase yang sedang "Paused", atau gangguan jaringan. Silakan coba gunakan VPN atau segarkan halaman ini.'
          : 'Database connection timeout (60s). This may be due to your ISP blocking Supabase, your project being "Paused", or temporary network issues. Please try using a VPN or refresh the page.')), 60000)
      );

      const { data, error } = await Promise.race([authPromise, timeoutPromise]);
      if (error) throw error;
      
      if (authMode === 'signup') {
        setSuccessMsg(language === 'ID' ? 'Pendaftaran berhasil! Silakan cek email Anda.' : 'Sign up successful! Please check your email.');
        setAuthMode('login');
      } else if (authMode === 'login') {
        // After successful login, if they have a local vault, prompt to unlock it
        if (config?.encryptedVault) {
          setAuthMode('unlock');
          setPassword(''); // clear password for vault unlock
        } else {
          onEnter();
        }
      }
    } catch (err: any) {
      setError(err.message || (language === 'ID' ? 'Terjadi kesalahan jaringan' : 'A network error occurred'));
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setIsDecrypting(true);
    try {
      const isTauri = typeof window !== 'undefined' && 
         (!!(window as any).__TAURI_INTERNALS__ || 
          !!(window as any).__TAURI__ ||
          window.location.host.includes('tauri.localhost'));

      // If user wants to link to an existing admin account, we can attempt a linkIdentity first 
      // if they are somehow already partially logged in, though AuthPage usually means not logged in.
      // But mainly, we just redirect. Supabase will handle matching if 'Link Identities' is enabled in Dashboard.
      const redirectUrl = typeof window !== 'undefined' && window.location.host.includes('localhost') 
          ? window.location.origin 
          : 'https://nexus-core-app.onrender.com';

      const { data, error } = await supabase.auth.signInWithOAuth({
        provider: 'google',
        options: {
          redirectTo: redirectUrl,
          queryParams: {
            // Force prompt to ensure the user picks the right Google account if they have multiple
            prompt: 'select_account'
          }
        }
      });
      if (error) throw error;
    } catch (err: any) {
      setError(err.message || (language === 'ID' ? 'Terjadi kesalahan saat login Google' : 'An error occurred during Google login'));
      setIsDecrypting(false);
    }
  };

  const handleUnlock = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (isDecrypting) return;
    
    const minLen = loginType === 'pin' ? 6 : 1;
    if (password.length < minLen) return;

    setError(null);
    setIsDecrypting(true);

    try {
      const freshConfig = await SystemConfigStore.forceSync();
      const vault = freshConfig.encryptedVault;
      
      if (!vault || !SecurityManager.isVaultValid(vault)) { 
        setError(language === 'ID' ? "Vault tidak ditemukan." : "Vault missing.");
        setIsDecrypting(false);
        return; 
      }

      const decryptedStr = await SecurityManager.unlock(vault, password);

      if (!decryptedStr) {
        setError(language === 'ID' ? "Kata sandi salah" : "Incorrect password");
        setIsDecrypting(false);
        return;
      }

      let keys = JSON.parse(decryptedStr);
      if (isTauri) {
        await invoke('push_decrypted_keys', { 
          keys: { exchange: keys.exchange || {}, env_keys: keys.envKeys || {} } 
        }).catch(err => console.error("Bridge Sync Error:", err));
      }

      setDecryptedSessionKeys({
        exchange: keys.exchange || {},
        envKeys: keys.envKeys || {}
      });

      updateConfig({
        ...freshConfig,
        isLocked: false,
        lastUnlock: new Date().toISOString()
      });
      
      onEnter();

    } catch (err: any) {
      setError(language === 'ID' ? "Dekripsi Gagal" : "Decryption Failed");
      setIsDecrypting(false);
    }
  };

  return (
    <div className={`fixed inset-0 z-[100] flex ${theme === 'dark' ? 'bg-[#0B0E14] text-white' : 'bg-slate-50 text-slate-900'} animate-in fade-in duration-200`}>
      {/* Left Pane - Image & Tagline */}
      <div className="hidden lg:flex relative w-1/2 bg-[#0B0E14] items-center justify-center overflow-hidden rounded-r-[2rem]">
        <img 
          src="/planet22-bg.jpg" 
          alt="Abstract colorful planet" 
          className="absolute inset-0 w-full h-full object-cover opacity-90 mix-blend-screen"
          referrerPolicy="no-referrer"
        />
        <div className="absolute inset-0 bg-gradient-to-b from-[#0B0E14]/60 via-[#0B0E14]/10 to-[#0B0E14] z-10"></div>
        
        <div className="absolute top-24 left-0 right-0 z-20 text-center px-12 flex justify-center">
          <h1 className="text-2xl xl:text-3xl font-bold tracking-tight leading-[1.1] text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 whitespace-nowrap">
            {language === 'ID' ? 'Ikuti Likuiditas / Eksekusi dengan Keyakinan.' : 'Follow Liquidity / Execute with Conviction.'}
          </h1>
        </div>
      </div>

      {/* Right Pane - Auth Form */}
      <div className={`relative w-full lg:w-1/2 flex flex-col ${theme === 'dark' ? 'bg-[#0B0E14]' : 'bg-white'}`}>
        {/* Header */}
        <div className="absolute top-0 left-0 right-0 p-6 flex justify-between items-center z-10">
          {/* Mobile Logo (Left) */}
          <div className="flex items-center gap-2 lg:hidden">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-emerald-500 flex items-center justify-center shadow-lg">
              <span className="text-white font-black text-sm tracking-tighter">NX</span>
            </div>
            <span className="text-xl font-black tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-emerald-500">NEXUS</span>
          </div>
          
          {/* Desktop Logo (Center) */}
          <div className="hidden lg:flex absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-emerald-500 flex items-center justify-center shadow-lg">
              <span className="text-white font-black text-sm tracking-tighter">NX</span>
            </div>
            <span className="text-xl font-black tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-emerald-500">NEXUS</span>
          </div>

          {/* Close Button (Right) */}
          <div className="ml-auto">
            <button 
              onClick={onClose}
              className={`p-2 rounded-full ${theme === 'dark' ? 'hover:bg-white/5 text-slate-400' : 'hover:bg-slate-100 text-slate-500'} transition-colors`}
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Form Container */}
        <div className="flex-1 flex flex-col items-center justify-center px-8 sm:px-16 md:px-24">
          <div className="w-full max-w-sm">
            <h2 className={`text-2xl font-bold text-center mb-8 ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>
              {authMode === 'unlock' 
                ? (language === 'ID' ? 'Buka Brankas' : 'Unlock Vault')
                : authMode === 'signup' 
                  ? (language === 'ID' ? 'Daftar Akun' : 'Create Account')
                  : (language === 'ID' ? 'Masuk' : 'Sign in')}
            </h2>

            {authMode !== 'unlock' && (
              <button 
                type="button"
                onClick={handleGoogleSignIn}
                className={`w-full flex items-center justify-center gap-3 px-4 py-3 border ${theme === 'dark' ? 'border-slate-800 hover:bg-white/5' : 'border-slate-200 hover:bg-slate-50'} rounded-lg transition-colors mb-6`}
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                </svg>
                <span className={`text-sm font-medium ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
                  {language === 'ID' ? 'Lanjutkan dengan Google' : 'Continue with Google'}
                </span>
              </button>
            )}

            {authMode !== 'unlock' && (
              <div className="flex items-center gap-4 mb-6">
                <div className={`flex-1 h-px ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-100'}`}></div>
                <span className={`text-xs font-medium ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>
                  {language === 'ID' ? 'atau dengan email' : 'or with email'}
                </span>
                <div className={`flex-1 h-px ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-100'}`}></div>
              </div>
            )}

            <div className={`${theme === 'dark' ? 'bg-[#0B0E14] border-slate-800' : 'bg-white border-slate-200'} border rounded-xl p-6 shadow-sm`}>
              {authMode === 'unlock' ? (
                <>
                  <div className="flex justify-center gap-2 mb-6">
                    <button 
                      type="button" 
                      onClick={() => setLoginType('pin')} 
                      className={`text-xs px-4 py-1.5 rounded-full transition-colors ${loginType === 'pin' ? 'bg-blue-600 text-white font-medium shadow-sm' : (theme === 'dark' ? 'text-slate-400 hover:bg-white/5' : 'text-slate-500 hover:bg-slate-100')}`}
                    >
                      Pin
                    </button>
                    <button 
                      type="button" 
                      onClick={() => setLoginType('password')} 
                      className={`text-xs px-4 py-1.5 rounded-full transition-colors ${loginType === 'password' ? 'bg-blue-600 text-white font-medium shadow-sm' : (theme === 'dark' ? 'text-slate-400 hover:bg-white/5' : 'text-slate-500 hover:bg-slate-100')}`}
                    >
                      Password
                    </button>
                  </div>

                  <form onSubmit={handleUnlock} className="space-y-4">
                    <div>
                      <input
                        type="password"
                        inputMode={loginType === 'pin' ? 'numeric' : 'text'}
                        value={password}
                        onChange={(e) => {
                          const val = e.target.value;
                          if (loginType === 'pin') {
                            if (/^\d*$/.test(val) && val.length <= 6) setPassword(val);
                          } else {
                            setPassword(val);
                          }
                        }}
                        placeholder={language === 'ID' ? `Masukkan ${loginType === 'pin' ? 'Pin' : 'Password'}` : `Enter ${loginType === 'pin' ? 'Pin' : 'Password'}`}
                        className={`w-full px-4 py-3 ${theme === 'dark' ? 'bg-[#0B0E14] border-slate-800 text-white focus:border-slate-600' : 'bg-white border-slate-200 text-slate-900 focus:border-slate-400'} border rounded-lg text-sm focus:outline-none transition-colors`}
                        autoFocus
                      />
                    </div>
                    
                    {error && (
                      <div className={`text-xs text-rose-500 flex items-center gap-1.5 p-2 rounded-lg border ${theme === 'dark' ? 'bg-rose-500/10 border-rose-500/20' : 'bg-rose-50 border-rose-100'}`}>
                        <AlertTriangle size={14} /> {error}
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={isDecrypting || !password}
                      className="w-full bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium py-3 rounded-lg transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
                    >
                      {isDecrypting ? (
                        <Loader2 size={18} className="animate-spin" />
                      ) : (
                        <>
                          <Unlock className="w-4 h-4" />
                          {language === 'ID' ? 'Buka Kunci' : 'Unlock'}
                        </>
                      )}
                    </button>

                    <div className="pt-2 flex flex-col items-center gap-2">
                      <button 
                         type="button"
                         onClick={async () => {
                            if (window.confirm(language === 'ID' 
                               ? 'Apakah Anda yakin ingin mereset Brankas Lokal? Ini akan menghapus kunci API bursa yang tersimpan. Anda harus memasukkannya kembali nanti.' 
                               : 'Are you sure you want to reset Local Vault? This will delete stored exchange API keys. You will need to re-enter them later.')) {
                               const freshConfig = await SystemConfigStore.forceSync();
                               updateConfig({ ...freshConfig, encryptedVault: null, isLocked: false });
                               setAuthMode('login');
                            }
                         }}
                         className={`text-[10px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'text-slate-600 hover:text-slate-400' : 'text-slate-400 hover:text-slate-600'} transition-colors`}
                      >
                         {language === 'ID' ? 'Lupa Password Vault? Reset Brankas' : 'Forgot Vault Password? Reset Vault'}
                      </button>

                      <button 
                         type="button"
                         onClick={async () => {
                            if (window.confirm(language === 'ID' 
                               ? 'Sistem akan keluar paksa dan menghapus seluruh sesi. Gunakan jika Anda stuck tidak bisa login.' 
                               : 'System will force logout and clear all sessions. Use this if you are stuck and cannot login.')) {
                               await supabase.auth.signOut();
                               localStorage.clear();
                               window.location.reload();
                            }
                         }}
                         className="text-[9px] text-rose-500/50 hover:text-rose-500 font-medium uppercase tracking-wider transition-colors"
                      >
                         {language === 'ID' ? 'Keluar Paksa & Reset Aplikasi' : 'Force Logout & Reset App'}
                      </button>
                    </div>
                  </form>
                </>
              ) : (
                <form onSubmit={handleSupabaseAuth} className="space-y-4">
                  <div>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder={language === 'ID' ? 'Alamat Email' : 'Email Address'}
                      className={`w-full px-4 py-3 mb-3 ${theme === 'dark' ? 'bg-[#0B0E14] border-slate-800 text-white focus:border-slate-600' : 'bg-white border-slate-200 text-slate-900 focus:border-slate-400'} border rounded-lg text-sm focus:outline-none transition-colors`}
                      required
                    />
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={language === 'ID' ? 'Kata Sandi' : 'Password'}
                      className={`w-full px-4 py-3 ${theme === 'dark' ? 'bg-[#0B0E14] border-slate-800 text-white focus:border-slate-600' : 'bg-white border-slate-200 text-slate-900 focus:border-slate-400'} border rounded-lg text-sm focus:outline-none transition-colors`}
                      required
                    />
                  </div>
                  
                  {error && (
                    <div className={`text-xs text-rose-500 flex items-center gap-1.5 p-2 rounded-lg border ${theme === 'dark' ? 'bg-rose-500/10 border-rose-500/20' : 'bg-rose-50 border-rose-100'}`}>
                      <AlertTriangle size={14} /> {error}
                    </div>
                  )}

                  {successMsg && (
                    <div className={`text-xs text-emerald-500 flex items-center gap-1.5 p-2 rounded-lg border ${theme === 'dark' ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-emerald-50 border-emerald-100'}`}>
                      <Mail size={14} /> {successMsg}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isDecrypting || !email || !password}
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium py-3 rounded-lg transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
                  >
                    {isDecrypting ? (
                      <Loader2 size={18} className="animate-spin" />
                    ) : (
                      <>
                        {authMode === 'signup' ? (language === 'ID' ? 'Daftar' : 'Sign Up') : (language === 'ID' ? 'Masuk' : 'Sign In')}
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className={`p-6 text-center border-t ${theme === 'dark' ? 'border-slate-800' : 'border-slate-100'}`}>
          {authMode === 'unlock' ? (
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>
              <button onClick={() => setAuthMode('login')} className="text-blue-600 hover:text-blue-500 font-medium transition-colors">
                {language === 'ID' ? 'Ganti Akun' : 'Switch Account'}
              </button>
            </p>
          ) : authMode === 'login' ? (
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>
              {language === 'ID' ? 'Tidak memiliki akun? ' : "Don't have an account? "}
              <button onClick={() => setAuthMode('signup')} className="text-blue-600 hover:text-blue-500 font-medium transition-colors">
                {language === 'ID' ? 'Daftar' : 'Sign up'}
              </button>
            </p>
          ) : (
            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>
              {language === 'ID' ? 'Sudah memiliki akun? ' : "Already have an account? "}
              <button onClick={() => setAuthMode('login')} className="text-blue-600 hover:text-blue-500 font-medium transition-colors">
                {language === 'ID' ? 'Masuk' : 'Sign in'}
              </button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
