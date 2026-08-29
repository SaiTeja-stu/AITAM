import { createContext, useContext, useState, useCallback } from 'react';
import { api, getToken, setToken } from './api.js';

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [token, setTok] = useState(getToken());
  const [error, setError] = useState('');

  const login = useCallback(async (loginId, password) => {
    setError('');
    try {
      const res = await api.login(loginId, password);
      setToken(res.accessToken);
      setTok(res.accessToken);
      return true;
    } catch (e) {
      setError(e.message || 'Login failed');
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    setToken('');
    setTok('');
  }, []);

  return (
    <AuthCtx.Provider value={{ token, isAuthed: !!token, login, logout, error }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
