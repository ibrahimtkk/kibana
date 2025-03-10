/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ExperimentalFeatures } from '../../../common/experimental_features';
import { allowedExperimentalValues } from '../../../common/experimental_features';

const ExperimentalFeaturesServiceMock = {
  init: jest.fn(),

  get: jest.fn(() => {
    const ff: ExperimentalFeatures = {
      ...allowedExperimentalValues,
      responseActionGetFileEnabled: true,
    };

    return ff;
  }),
};

export { ExperimentalFeaturesServiceMock as ExperimentalFeaturesService };
