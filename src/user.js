import API, { JSONHTTPError } from 'micro-api-client';

import Admin from './admin';

const ExpiryMargin = 60 * 1000;
const storageKey = 'gotrue.user';
const refreshPromises = {};
let currentUser = null;
let store = null;
const forbiddenUpdateAttributes = { api: 1, token: 1, audience: 1, url: 1 };
const forbiddenSaveAttributes = { api: 1 };
const isBrowser = () => typeof window !== 'undefined';

export default class User {
  constructor(api, tokenResponse, audience, userStore) {
    this.api = api;
    this.url = api.apiURL;
    this.audience = audience;
    this._processTokenResponse(tokenResponse);
    store = userStore;
    currentUser = this;
  }

  static removeSavedSession(receivedStore) {
    return isBrowser() && receivedStore.removeItem(storageKey);
  }

  static async recoverSession(apiInstance, receivedStore) {
    if (currentUser) {
      return currentUser;
    }

    const json = isBrowser() && (await receivedStore.getItem(storageKey));
    if (json) {
      try {
        const data = JSON.parse(json);
        const { url, token, audience } = data;
        if (!url || !token) {
          return null;
        }

        const api = apiInstance || new API(url, {});
        return new User(api, token, audience, receivedStore)._saveUserData(data, true);
      } catch (error) {
        console.error(new Error(`Gotrue-js: Error recovering session: ${error}`));
        return null;
      }
    }

    return null;
  }

  get admin() {
    return new Admin(this);
  }

  update(attributes) {
    return this._request('/user', {
      method: 'PUT',
      body: JSON.stringify(attributes),
    }).then((response) => this._saveUserData(response)._refreshSavedSession());
  }

  jwt(forceRefresh) {
    const token = this.tokenDetails();
    if (token === null || token === undefined) {
      return Promise.reject(new Error(`Gotrue-js: failed getting jwt access token`));
    }
    const { expires_at, refresh_token, access_token } = token;
    if (forceRefresh || expires_at - ExpiryMargin < Date.now()) {
      return this._refreshToken(refresh_token);
    }
    return Promise.resolve(access_token);
  }

  logout() {
    return this._request('/logout', { method: 'POST' })
      .then(this.clearSession.bind(this))
      .catch(this.clearSession.bind(this));
  }

  async _refreshToken(refresh_token) {
    if (refreshPromises[refresh_token]) {
      return refreshPromises[refresh_token];
    }

    try {
      const response = await this.api.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=refresh_token&refresh_token=${refresh_token}`,
      });
      delete refreshPromises[refresh_token];
      this._processTokenResponse(response);
      await this._refreshSavedSession();
      refreshPromises[refresh_token] = this.token.access_token;
    } catch (error) {
      delete refreshPromises[refresh_token];
      await this.clearSession();
      throw error;
    }
  }

  async _request(path, options = {}) {
    options.headers = options.headers || {};

    const aud = options.audience || this.audience;
    if (aud) {
      options.headers['X-JWT-AUD'] = aud;
    }

    try {
      const token = await this.jwt();
      return await this.api.request(path, {
        headers: Object.assign(options.headers, {
          Authorization: `Bearer ${token}`,
        }),
        ...options,
      });
    } catch (error) {
      if (error instanceof JSONHTTPError && error.json) {
        if (error.json.msg) {
          error.message = error.json.msg;
        } else if (error.json.error) {
          error.message = `${error.json.error}: ${error.json.error_description}`;
        }
      }
      throw error;
    }
  }

  getUserData() {
    return this._request('/user')
      .then(this._saveUserData.bind(this))
      .then(this._refreshSavedSession.bind(this));
  }

  _saveUserData(attributes, fromStorage) {
    for (const key in attributes) {
      if (key in User.prototype || key in forbiddenUpdateAttributes) {
        continue;
      }
      this[key] = attributes[key];
    }
    if (fromStorage) {
      this._fromStorage = true;
    }
    return this;
  }

  _processTokenResponse(tokenResponse) {
    this.token = tokenResponse;
    try {
      const claims = JSON.parse(urlBase64Decode(tokenResponse.access_token.split('.')[1]));
      this.token.expires_at = claims.exp * 1000;
    } catch (error) {
      console.error(new Error(`Gotrue-js: Failed to parse tokenResponse claims: ${error}`));
    }
  }

  async _refreshSavedSession() {
    // only update saved session if we previously saved something
    if (isBrowser() && (await store.getItem(storageKey))) {
      await this._saveSession();
    }
    return this;
  }

  get _details() {
    const userCopy = {};
    for (const key in this) {
      if (key in User.prototype || key in forbiddenSaveAttributes) {
        continue;
      }
      userCopy[key] = this[key];
    }
    return userCopy;
  }

  async _saveSession() {
    isBrowser() && (await store.setItem(storageKey, JSON.stringify(this._details)));
    return this;
  }

  tokenDetails() {
    return this.token;
  }

  async clearSession() {
    await User.removeSavedSession(store);
    this.token = null;
    currentUser = null;
  }
}

function urlBase64Decode(str) {
  // From https://jwt.io/js/jwt.js
  let output = str.replace(/-/g, '+').replace(/_/g, '/');
  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += '==';
      break;
    case 3:
      output += '=';
      break;
    default:
      throw 'Illegal base64url string!';
  }

  // polifyll https://github.com/davidchambers/Base64.js
  const result = window.atob(output);
  try {
    return decodeURIComponent(escape(result));
  } catch {
    return result;
  }
}
