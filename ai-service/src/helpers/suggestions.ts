import { NatsService, Singleton } from '@guardian/common';
import { GenerateUUIDv4, MessageAPI } from '@guardian/interfaces';

/**
 * AISuggestionService service
 */
@Singleton
export class AISuggestionService extends NatsService {
    constructor() {
        super();

        this.configureAvailableEvents([MessageAPI.SUGGESTIONS_GET_ANSWER, MessageAPI.VECTOR_REBUILD])
    }
    /**
     * Message queue name
     */
    public messageQueueName = 'ai-suggestions';

    /**
     * Reply subject
     * @private
     */
    public replySubject = 'ai-service-' + GenerateUUIDv4();

    registerListener(event: string, cb: Function): void {
        this.getMessages(event, cb);
    }
}
