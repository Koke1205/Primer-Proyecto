(() => {
  const apiOrigin = window.CASINO_API_ORIGIN
    || `${window.location.protocol === 'https:' ? 'https:' : 'http:'}//${window.location.hostname || '127.0.0.1'}:8000`;
  const apiBase = `${apiOrigin.replace(/\/$/, '')}/api/v1`;
  const tokenKey = 'casino_session_token';

  function token() {
    return sessionStorage.getItem(tokenKey);
  }

  function signOut() {
    sessionStorage.removeItem(tokenKey);
    window.location.href = 'auth.html';
  }

  function loginRedirect() {
    const next = `${window.location.pathname.split('/').pop() || 'lobby.html'}${window.location.search}`;
    window.location.replace(`auth.html?next=${encodeURIComponent(next)}`);
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (token()) headers.set('Authorization', `Bearer ${token()}`);
    const response = await fetch(`${apiBase}${path}`, {...options, headers});
    let data;
    try {
      data = await response.json();
    } catch (error) {
      if (!response.ok) throw new Error(`Error del servidor (${response.status}).`);
      throw new Error('El servidor devolvió una respuesta inválida.');
    }
    if (response.status === 401 && token()) {
      sessionStorage.removeItem(tokenKey);
      loginRedirect();
      throw new Error('La sesión venció. Inicia sesión nuevamente.');
    }
    if (!response.ok) {
      const error = new Error(typeof data.detail === 'string' ? data.detail : 'No se pudo completar la solicitud.');
      error.status = response.status;
      throw error;
    }
    return data;
  }

  async function requireSession() {
    if (!token()) {
      loginRedirect();
      return null;
    }
    try {
      const user = await api('/auth/me');
      window.casinoUser = user;
      return user;
    } catch (error) {
      if (error.status === 401) return null;
      throw error;
    }
  }

  function showBalance(element, account) {
    if (!element || !account) return;
    element.textContent = account.unlimited_credits
      ? '∞ · INFINITO'
      : `${Math.round(account.balance).toLocaleString('es-CL')} CLP`;
  }

  window.CasinoAuth = {api, requireSession, showBalance, signOut, token};
})();
