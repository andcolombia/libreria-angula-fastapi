// This api will come in the next version

import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'https://qaautenticaciondigital.and.gov.co',
  redirectUri: window.location.origin + '/inicio',
  silentRefreshRedirectUri: window.location.origin + '/silent-refresh.html',
  clientId: 'spa-demoQA',
  responseType: 'code',
  scope: 'openid profile email offline_access ccd_api',
  showDebugInformation: true,
  sessionChecksEnabled: true,
};
