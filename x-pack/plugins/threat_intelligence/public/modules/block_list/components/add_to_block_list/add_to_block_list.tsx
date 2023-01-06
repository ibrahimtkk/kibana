/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { VFC } from 'react';
import { EuiContextMenuItem } from '@elastic/eui';
import { FormattedMessage } from '@kbn/i18n-react';
import { useBlockListContext } from '../../../indicators/hooks/use_block_list_context';
import { useSetUrlParams } from '../../hooks/use_set_url_params';

export interface AddToBlockListProps {
  /**
   *
   */
  data: string;
  /**
   * Used for unit and e2e tests.
   */
  ['data-test-subj']?: string;
  /**
   * Click event to close the popover in the parent component
   */
  onClick?: () => void;
}

export const AddToBlockListContextMenu: VFC<AddToBlockListProps> = ({
  data,
  'data-test-subj': dataTestSub,
  onClick,
}) => {
  const { setBlockListIndicatorValue } = useBlockListContext();

  const setUrlParams = useSetUrlParams();

  const menuItemClicked = () => {
    if (onClick) onClick();
    setBlockListIndicatorValue(data);
    setUrlParams({ show: 'create' });
  };

  return (
    <EuiContextMenuItem
      key="investigateInTime"
      onClick={() => menuItemClicked()}
      data-test-subj={dataTestSub}
    >
      <FormattedMessage
        defaultMessage="Add blocklist entry"
        id="xpack.threatIntelligence.addToBlockList"
      />
    </EuiContextMenuItem>
  );
};
