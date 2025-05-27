import { ApplicationState, LargePayloadContainer, MessageBrokerChannel, mongoForLoggingInitialization, OldSecretManager, PinoLogger, pinoLoggerInitialization, SecretManager } from '@guardian/common';
import { ApplicationStates } from '@guardian/interfaces';
import { PolicyContainer } from './helpers/policy-container.js';
import { startMetricsServer } from './utils/metrics.js';

export const obj = {};

Promise.all([
    MessageBrokerChannel.connect('policy-service'),
    mongoForLoggingInitialization()
]).then(async values => {
    const [cn, loggerMongo] = values;

    const logger: PinoLogger = pinoLoggerInitialization(loggerMongo);

    const state = new ApplicationState();
    await state.setServiceName('POLICY_SERVICE').setConnection(cn).init();
    await state.updateState(ApplicationStates.STARTED);

    state.updateState(ApplicationStates.INITIALIZING);

    // await new PolicyContainer().setConnection(cn).init();

    const c = new PolicyContainer(logger);
    await c.setConnection(cn).init();

    await new OldSecretManager().setConnection(cn).init();
    const secretManager = SecretManager.New();

    let { SERVICE_JWT_PUBLIC_KEY } = await secretManager.getSecrets(`publickey/jwt-service/${process.env.SERVICE_CHANNEL}`);
    if (!SERVICE_JWT_PUBLIC_KEY) {
        SERVICE_JWT_PUBLIC_KEY = process.env.SERVICE_JWT_PUBLIC_KEY;
        if (SERVICE_JWT_PUBLIC_KEY.length < 8) {
            throw new Error(`${process.env.SERVICE_CHANNEL} service jwt keys not configured`);
        }
        await secretManager.setSecrets(`publickey/jwt-service/${process.env.SERVICE_CHANNEL}`, {SERVICE_JWT_PUBLIC_KEY});
    }

    let { SERVICE_JWT_SECRET_KEY } = await secretManager.getSecrets(`secretkey/jwt-service/${process.env.SERVICE_CHANNEL}`);

    if (!SERVICE_JWT_SECRET_KEY) {
        SERVICE_JWT_SECRET_KEY = process.env.SERVICE_JWT_SECRET_KEY;
        if (SERVICE_JWT_SECRET_KEY.length < 8) {
            throw new Error(`${process.env.SERVICE_CHANNEL} service jwt keys not configured`);
        }
        await secretManager.setSecrets(`secretkey/jwt-service/${process.env.SERVICE_CHANNEL}`, {SERVICE_JWT_SECRET_KEY});
    }

    c.configureSecretManager(secretManager);

    const maxPayload = parseInt(process.env.MQ_MAX_PAYLOAD, 10);
    if (Number.isInteger(maxPayload)) {
        new LargePayloadContainer().runServer();
    }
    await logger.info('Policy service started', ['POLICY_SERVICE'], null);

    await state.updateState(ApplicationStates.READY);

    startMetricsServer();
}, (reason) => {
    console.log(reason);
    process.exit(0);
});
