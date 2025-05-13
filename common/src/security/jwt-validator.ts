import jwt from 'jsonwebtoken';

export class JwtValidator {
  private static privateKey: string | null = null;

  private static async loadPrivateKey(mgr): Promise<string> {
    if (!this.privateKey) {
      const svc = process.env.SERVICE_CHANNEL;
      const sec = await mgr.getSecrets(`secretkey/jwt-service/${svc}`);
      if (!sec?.SERVICE_JWT_SECRET_KEY) {
        throw new Error(`JWTValidator: no privateKey at secretkey/jwt-service/${svc}`);
      }
      this.privateKey = sec.SERVICE_JWT_SECRET_KEY;
    }
    return this.privateKey;
  }

  public static async sign(mgr): Promise<string> {
    if (!mgr) {
      return '';
    }

    const key = await this.loadPrivateKey(mgr);

    return jwt.sign(
      { sub: process.env.SERVICE_CHANNEL! },
      key,
      { algorithm: 'RS256' }
    );
  }

  public static async verify(token: string, mgr): Promise<string> {
    if (!mgr) return '';
    if (!token) return '';
    // if (!token) throw new Error('JWTValidator: missing token');
    const decoded = jwt.decode(token) as any;
    const signer  = decoded?.sub;
    if (!signer) throw new Error('JWTValidator: missing sub claim');

    const sec = await mgr.getSecrets(`publickey/jwt-service/${signer}`);

    if (!sec?.SERVICE_JWT_PUBLIC_KEY) {
      throw new Error(`JWTValidator: no publicKey at publickey/jwt-service/${signer}`);
    }

    try {
      const payload = jwt.verify(token, sec.SERVICE_JWT_PUBLIC_KEY, { algorithms: ['RS256'] }) as any;
      if (payload.sub !== signer) {
        throw new Error('JWTValidator: sub mismatch');
      }
      return signer;
    } catch {
      throw new Error('JWTValidator: invalid or expired token');
    }
  }
}
