/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ENDPOINT_ARTIFACT_LISTS } from '@kbn/securitysolution-list-constants';
import type { HttpStart } from '@kbn/core/public';
import type { CreateExceptionListSchema } from '@kbn/securitysolution-io-ts-list-types';
import { ExceptionListTypeEnum } from '@kbn/securitysolution-io-ts-list-types';
import { ExceptionsListApiClient } from '../management/services/exceptions_list/exceptions_list_api_client';

const LIST_DEFINITION: CreateExceptionListSchema = {
  name: ENDPOINT_ARTIFACT_LISTS.threatIntelligence.name,
  namespace_type: 'agnostic',
  description: ENDPOINT_ARTIFACT_LISTS.threatIntelligence.description,
  list_id: ENDPOINT_ARTIFACT_LISTS.threatIntelligence.id,
  type: ExceptionListTypeEnum.ENDPOINT_THREAT_INTELLIGENCE,
};

/**
 * Exceptions Api client class using ExceptionsListApiClient as base class
 * It follow the Singleton pattern.
 * Please, use the getInstance method instead of creating a new instance when using this implementation.
 */
export class ThreatIntelligenceExceptionsApiClient extends ExceptionsListApiClient {
  constructor(http: HttpStart) {
    super(http, ENDPOINT_ARTIFACT_LISTS.threatIntelligence.id, LIST_DEFINITION);
  }

  public static getInstance(http: HttpStart): ExceptionsListApiClient {
    return super.getInstance(http, ENDPOINT_ARTIFACT_LISTS.threatIntelligence.id, LIST_DEFINITION);
  }
}
