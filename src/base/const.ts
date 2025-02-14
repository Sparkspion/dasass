export enum ROLES {
  ADMIN = 'admin',
  USER = 'user',
}

export const ALL_ROLES = [ROLES.ADMIN, ROLES.USER];

export const COOKIE = {
  REFRESH_TOKEN: 'refreshToken',
};

export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  SERVER_ERROR: 500,
};

export const OTP_EXPIRY_DURATION = 5 * 60 * 1000; // 5 minutes
export const OTP_DIGITS = 6;
export const OTP_DURATION = 300; // OTP valid for 5 minutes

export const SALT = 10;
