/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import moment from 'moment';
import { i18n } from '@kbn/i18n';
import { useKibana } from '@kbn/kibana-react-plugin/public';
import { getShortTimeStamp } from '../../../utils/monitor_test_result/timestamp';
import { PLUGIN } from '../../../../../../common/constants/plugin';
import { useBreadcrumbs } from '../../../hooks';
import { SyntheticsJourneyApiResponse } from '../../../../../../common/runtime_types';

interface ActiveStep {
  monitor: {
    id: string;
    name?: string;
  };
}

interface Props {
  details: SyntheticsJourneyApiResponse['details'];
  activeStep?: ActiveStep;
  performanceBreakDownView?: boolean;
}

export const useMonitorBreadcrumb = ({
  details,
  activeStep,
  performanceBreakDownView = false,
}: Props) => {
  const kibana = useKibana();
  const appPath = kibana.services.application?.getUrlForApp(PLUGIN.ID) ?? '';

  useBreadcrumbs([
    ...(activeStep?.monitor
      ? [
          {
            text: activeStep?.monitor?.name || activeStep?.monitor.id,
            href: `${appPath}/monitor/${btoa(activeStep?.monitor.id)}`,
          },
        ]
      : []),
    ...(details?.journey?.monitor?.check_group
      ? [
          {
            text: getShortTimeStamp(moment(details?.timestamp)),
            href: `${appPath}/journey/${details.journey.monitor.check_group}/steps`,
          },
        ]
      : []),
    ...(performanceBreakDownView
      ? [
          {
            text: i18n.translate('xpack.synthetics.synthetics.performanceBreakDown.label', {
              defaultMessage: 'Performance breakdown',
            }),
          },
        ]
      : []),
  ]);
};
