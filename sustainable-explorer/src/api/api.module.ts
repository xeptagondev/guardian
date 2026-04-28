import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import configuration from '@shared/config/configuration';

// Database
import { NetworkDataSourceRegistry } from './database/network-datasource.registry';

// Controllers
import { RegistriesController } from './controllers/registries.controller';
import { MethodologiesController } from './controllers/methodologies.controller';
import { PolicySchemasController } from './controllers/policy-schemas.controller';
import { PolicyDetailController } from './controllers/policy-detail.controller';

// Services
import { RegistriesService } from './services/registries.service';
import { MethodologiesService } from './services/methodologies.service';
import { PolicySchemasService } from './services/policy-schemas.service';
import { PolicyDetailService } from './services/policy-detail.service';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            load: [configuration],
        }),
    ],
    controllers: [
        RegistriesController,
        MethodologiesController,
        PolicySchemasController,
        PolicyDetailController,
    ],
    providers: [
        NetworkDataSourceRegistry,
        RegistriesService,
        MethodologiesService,
        PolicySchemasService,
        PolicyDetailService,
    ],
})
export class ApiModule {}
