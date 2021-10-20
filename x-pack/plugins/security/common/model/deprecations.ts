/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// eslint-disable-next-line @kbn/eslint/no-restricted-paths
import type { DeprecationsDetails, GetDeprecationsContext } from '../../../../../src/core/server';
import type { Role } from './role';

export interface PrivilegeDeprecationsRolesResponse {
  roles?: Role[];
  errors?: DeprecationsDetails[];
}

export interface PrivilegeDeprecationsRolesRequest {
  context: GetDeprecationsContext;
  featureId?: string;
}
export interface PrivilegeDeprecationsService {
  getKibanaRoles: (
    args: PrivilegeDeprecationsRolesRequest
  ) => Promise<PrivilegeDeprecationsRolesResponse>;
}
