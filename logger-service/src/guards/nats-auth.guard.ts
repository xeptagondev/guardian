import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { NatsContext }  from '@nestjs/microservices';
import { JwtValidator, SecretManager } from '@guardian/common';

@Injectable()
export class NatsAuthGuard implements CanActivate {
  constructor(private readonly allowedCommands: string[]) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (ctx.getType() !== 'rpc') {
      return true;
    }

    const rpc = ctx.switchToRpc();
    const nats = rpc.getContext<NatsContext>();
    const subject = nats.getSubject();

    if (!this.allowedCommands.includes(subject)) {
      throw new ForbiddenException(`NATS ACL: "${subject}" not allowed`);
    }

    const rawMsg = ctx.getArgByIndex(1) as { headers?: any };
    const token = rawMsg?.headers?.get('serviceToken');
    if (!token) {
      throw new ForbiddenException('Missing serviceToken header');
    }

    await JwtValidator.verify(token, SecretManager.New());

    return true;
  }
}
