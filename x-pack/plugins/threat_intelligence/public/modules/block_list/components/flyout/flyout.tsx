/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { VFC } from 'react';
import {
  EntriesArray,
  ExceptionListItemSchema,
  ExceptionListItemType,
  ListId,
  ListOperator,
} from '@kbn/securitysolution-io-ts-list-types';
import { NonEmptyOrNullableStringArray } from '@kbn/securitysolution-io-ts-types';
import { BlockListForm } from '../form';
import { useSecurityContext } from '../../../../hooks/use_security_context';

export interface BlockListFlyoutProps {
  /**
   * Indicator file-hash value (sha256, sh1 or md5) to pass to the block list flyout.
   */
  indicatorFileHash: string;
}

/**
 * Component calling the block list flyout (retrieved from the SecuritySolution plugin via context).
 */
export const BlockListFlyout: VFC<BlockListFlyoutProps> = ({ indicatorFileHash }) => {
  const { blockList } = useSecurityContext();
  const Component = blockList.getFlyoutComponent();
  const exceptionListApiClient = blockList.exceptionListApiClient;

  const field: string = 'file.hash.*';
  const operator: ListOperator = 'included';
  const entryType = 'match_any';
  const value: NonEmptyOrNullableStringArray = [indicatorFileHash];
  const entries: EntriesArray = [
    {
      field,
      operator,
      type: entryType,
      value,
    },
  ];

  // const listId: ListId = 'endpoint_threat_intelligence';
  const listId: ListId = 'endpoint_blocklists';
  const itemType: ExceptionListItemType = 'simple';
  const item: ExceptionListItemSchema = {
    list_id: listId,
    entries,
    type: itemType,
  };

  const props = {
    apiClient: exceptionListApiClient,
    item,
    policies: [],
    policiesIsLoading: false,
    FormComponent: BlockListForm,
    onSuccess: () => {
      console.log('success');
    },
    onClose: () => {
      console.log('close');
    },
    labels: {},
    'data-test-subj': 'test',
    size: 'm',
  };

  return <Component {...props} />;
};
