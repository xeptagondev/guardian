import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ProjectsService } from '../services/projects.service';
import { PaginatedProjectsDto, ProjectQueryDto, ProjectResponseDto } from '../dto/project.dto';

@ApiTags('projects')
@Controller('api/v1/:network')
export class ProjectsController {
    constructor(private readonly projectsService: ProjectsService) {}

    @Get('methodologies/:id/projects')
    @ApiOperation({
        summary: 'List projects extracted under a methodology',
        description:
            'Returns canonical project records extracted from VCs in the methodology\'s DYNAMIC topics. ' +
            'Extraction is driven by the project schema identifier + field matcher in the worker.',
    })
    @ApiParam({ name: 'network', enum: ['mainnet', 'testnet', 'previewnet'] })
    @ApiParam({ name: 'id', description: 'Methodology / policy topic ID' })
    @ApiResponse({ status: 200, type: PaginatedProjectsDto })
    async listByMethodology(
        @Param('network') network: string,
        @Param('id') methodologyId: string,
        @Query() query: ProjectQueryDto,
    ) {
        return this.projectsService.listByMethodology(network, methodologyId, query);
    }

    @Get('projects')
    @ApiOperation({
        summary: 'List all extracted projects across methodologies',
        description: 'Paginated, filterable list of canonical project records on the given network.',
    })
    @ApiParam({ name: 'network', enum: ['mainnet', 'testnet', 'previewnet'] })
    @ApiResponse({ status: 200, type: PaginatedProjectsDto })
    async listAll(
        @Param('network') network: string,
        @Query() query: ProjectQueryDto,
    ) {
        return this.projectsService.listAll(network, query);
    }

    @Get('projects/:id')
    @ApiOperation({
        summary: 'Get a single extracted project (with raw VC and provenance)',
    })
    @ApiParam({ name: 'network', enum: ['mainnet', 'testnet', 'previewnet'] })
    @ApiParam({ name: 'id', description: 'Project row id' })
    @ApiResponse({ status: 200, type: ProjectResponseDto })
    @ApiResponse({ status: 404, description: 'Project not found' })
    async findById(
        @Param('network') network: string,
        @Param('id') id: string,
    ) {
        return this.projectsService.findById(network, id);
    }
}
