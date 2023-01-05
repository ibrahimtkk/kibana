/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useState, useCallback, memo, useEffect, useRef } from 'react';
import {
  EuiForm,
  EuiFormRow,
  EuiFieldText,
  EuiTextArea,
  EuiHorizontalRule,
  EuiText,
  EuiSpacer,
  EuiTitle,
  EuiFlexGroup,
  EuiFlexItem,
} from '@elastic/eui';
import type { BlocklistConditionEntryField } from '@kbn/securitysolution-utils';
import { isOneOfOperator } from '@kbn/securitysolution-list-utils';
import type { ExceptionListItemSchema } from '@kbn/securitysolution-io-ts-list-types';
import { uniq } from 'lodash';

import { CreateExceptionListItemSchema } from '@kbn/securitysolution-io-ts-list-types';
import { ArtifactFormComponentOnChangeCallbackProps } from '@kbn/security-solution-plugin/public/management/components/artifact_list_page';
import { i18n } from '@kbn/i18n';
import { useSecurityContext } from '../../../../hooks';
import type { EffectedPolicySelection } from '../../../../components/effected_policy_select';

import type { PolicyData } from '../../../../../../common/endpoint/types';

export const BLOCK_LIST_NAME_TEST_ID = 'tiBlockListName';
export const BLOCK_LIST_DESCRIPTION_TEST_ID = 'tiBlockListDescription';

export const DETAILS_HEADER = i18n.translate('xpack.threatIntelligence.blocklist.details.header', {
  defaultMessage: 'Details',
});

export const DETAILS_HEADER_DESCRIPTION = i18n.translate(
  'xpack.threatIntelligence.blocklist.details.header.description',
  {
    defaultMessage:
      'The blocklist prevents selected applications from running on your hosts by extending the list of processes the Endpoint considers malicious.',
  }
);

export const NAME_LABEL = i18n.translate('xpack.threatIntelligence.blocklist.name.label', {
  defaultMessage: 'Name',
});

export const DESCRIPTION_LABEL = i18n.translate(
  'xpack.threatIntelligence.blocklist.description.label',
  {
    defaultMessage: 'Description',
  }
);

export const CONDITIONS_HEADER = i18n.translate(
  'xpack.threatIntelligence.blocklist.conditions.header',
  {
    defaultMessage: 'Conditions',
  }
);

export const FIELD_LABEL = i18n.translate('xpack.threatIntelligence.blocklist.field.label', {
  defaultMessage: 'Field',
});

export const OPERATOR_LABEL = i18n.translate('xpack.threatIntelligence.blocklist.operator.label', {
  defaultMessage: 'Operator',
});

export const VALUE_LABEL = i18n.translate('xpack.threatIntelligence.blocklist.value.label', {
  defaultMessage: 'Value',
});

export const POLICY_SELECT_DESCRIPTION = i18n.translate(
  'xpack.threatIntelligence.blocklist.policyAssignmentSectionDescription',
  {
    defaultMessage:
      'Assign this blocklist globally across all policies, or assign it to specific policies.',
  }
);

export const ERRORS = {
  NAME_REQUIRED: i18n.translate('xpack.threatIntelligence.blocklist.errors.name.required', {
    defaultMessage: 'Name is required',
  }),
  VALUE_REQUIRED: i18n.translate('xpack.threatIntelligence.blocklist.errors.values.required', {
    defaultMessage: 'Field entry must have a value',
  }),
  INVALID_HASH: i18n.translate('xpack.threatIntelligence.blocklist.errors.values.invalidHash', {
    defaultMessage: 'Invalid hash value',
  }),
  DUPLICATE_VALUES: i18n.translate(
    'xpack.threatIntelligence.blocklist.warnings.values.duplicateValues',
    {
      defaultMessage: 'One or more duplicate values removed',
    }
  ),
};

export const BY_POLICY_ARTIFACT_TAG_PREFIX = 'policy:';
export const GLOBAL_ARTIFACT_TAG = `${BY_POLICY_ARTIFACT_TAG_PREFIX}all`;

export interface BlocklistEntry {
  field: BlocklistConditionEntryField;
  operator: 'included';
  type: 'match_any';
  value: string[];
}

type ERROR_KEYS = keyof typeof ERRORS;

type ItemValidationNodes = {
  [K in ERROR_KEYS]?: React.ReactNode;
};

interface ItemValidation {
  name: ItemValidationNodes;
  value: ItemValidationNodes;
}

function createValidationMessage(message: string): React.ReactNode {
  return <div>{message}</div>;
}

function isValid(itemValidation: ItemValidation): boolean {
  return !Object.values(itemValidation).some((errors) => Object.keys(errors).length);
}

export const isArtifactGlobal = (item: Pick<ExceptionListItemSchema, 'tags'>): boolean => {
  return (item.tags ?? []).find((tag) => tag === GLOBAL_ARTIFACT_TAG) !== undefined;
};

export function isGlobalPolicyEffected(tags?: string[]): boolean {
  return tags !== undefined && tags.find((tag) => tag === GLOBAL_ARTIFACT_TAG) !== undefined;
}

const HASH_LENGTHS: readonly number[] = [
  32, // MD5
  40, // SHA1
  64, // SHA256
];
const INVALID_CHARACTERS_PATTERN = /[^0-9a-f]/i;
export const isValidHash = (value: string) =>
  HASH_LENGTHS.includes(value.length) && !INVALID_CHARACTERS_PATTERN.test(value);

export interface BlockListFormProps {
  /**
   * Contains the values used in the form, operator and indicator file hash value.
   */
  item: CreateExceptionListItemSchema;
  /**
   *
   */
  policies: PolicyData[];
  /**
   *
   */
  policiesIsLoading: boolean;

  /**
   * Reports the state of the form data and the current updated item
   */
  onChange(formStatus: ArtifactFormComponentOnChangeCallbackProps): void;
}

/**
 * Form component displayed in the block list flyout.
 * The indicator-related values are pre-populated and readonly.
 * The user can only input the name, description and the policies section.
 */
export const BlockListForm = memo<BlockListFormProps>(
  ({ item, policies, policiesIsLoading, onChange }) => {
    const { blockList } = useSecurityContext();
    const EffectedPolicySelect = blockList.getFormEffectedPolicy();

    // @ts-ignore
    const indicatorFileHash: string = item.entries[0].value[0];

    const [visited, setVisited] = useState<{ name: boolean; value: boolean }>({
      name: false,
      value: false,
    });
    const warningsRef = useRef<ItemValidation>({ name: {}, value: {} });
    const errorsRef = useRef<ItemValidation>({ name: {}, value: {} });
    const [hasFormChanged, setHasFormChanged] = useState(false);

    const { licenseService } = useSecurityContext();
    const isPlatinumPlus = licenseService.isPlatinumPlus();

    const isGlobal = useMemo(() => isArtifactGlobal(item as ExceptionListItemSchema), [item]);
    const [selectedPolicies, setSelectedPolicies] = useState<PolicyData[]>([]);

    // select policies if editing
    useEffect(() => {
      if (hasFormChanged) return;
      const policyIds = item.tags?.map((tag) => tag.split(':')[1]) ?? [];
      if (!policyIds.length) return;
      const policiesData = policies.filter((policy) => policyIds.includes(policy.id));

      setSelectedPolicies(policiesData);
    }, [hasFormChanged, item.tags, policies]);

    const validateValues = useCallback((nextItem: BlockListFormProps['item']) => {
      const { field = 'file.hash.*', value: values = [] } = (nextItem.entries[0] ??
        {}) as BlocklistEntry;

      const newValueWarnings: ItemValidationNodes = {};
      const newNameErrors: ItemValidationNodes = {};
      const newValueErrors: ItemValidationNodes = {};

      // error if name empty
      if (!nextItem.name.trim()) {
        newNameErrors.NAME_REQUIRED = createValidationMessage(ERRORS.NAME_REQUIRED);
      }

      // error if no values
      if (!values.length) {
        newValueErrors.VALUE_REQUIRED = createValidationMessage(ERRORS.VALUE_REQUIRED);
      }

      // error if invalid hash
      if (field === 'file.hash.*' && values.some((value) => !isValidHash(value))) {
        newValueErrors.INVALID_HASH = createValidationMessage(ERRORS.INVALID_HASH);
      }

      // warn if duplicates
      if (values.length !== uniq(values).length) {
        newValueWarnings.DUPLICATE_VALUES = createValidationMessage(ERRORS.DUPLICATE_VALUES);
      }

      warningsRef.current = { ...warningsRef.current, value: newValueWarnings };
      errorsRef.current = { name: newNameErrors, value: newValueErrors };
    }, []);

    const handleOnNameBlur = useCallback(() => {
      validateValues(item);
      setVisited((prevVisited) => ({ ...prevVisited, name: true }));
    }, [item, validateValues]);

    const handleOnNameChange = useCallback(
      (event: React.ChangeEvent<HTMLInputElement>) => {
        const nextItem = {
          ...item,
          name: event.target.value,
        };

        validateValues(nextItem);
        onChange({
          isValid: isValid(errorsRef.current),
          item: nextItem,
        });
        setHasFormChanged(true);
      },
      [validateValues, onChange, item]
    );

    const handleOnDescriptionChange = useCallback(
      (event: React.ChangeEvent<HTMLTextAreaElement>) => {
        const nextItem = {
          ...item,
          description: event.target.value,
        };
        validateValues(nextItem);

        onChange({
          isValid: isValid(errorsRef.current),
          item: nextItem,
        });
        setHasFormChanged(true);
      },
      [onChange, item, validateValues]
    );

    const handleOnPolicyChange = useCallback(
      (change: EffectedPolicySelection) => {
        const tags = change.isGlobal
          ? [GLOBAL_ARTIFACT_TAG]
          : change.selected.map((policy) => `${BY_POLICY_ARTIFACT_TAG_PREFIX}${policy.id}`);

        const nextItem = { ...item, tags };

        // Preserve old selected policies when switching to global
        if (!change.isGlobal) {
          setSelectedPolicies(change.selected);
        }
        validateValues(nextItem);
        onChange({
          isValid: isValid(errorsRef.current),
          item: nextItem,
        });
        setHasFormChanged(true);
      },
      [validateValues, onChange, item]
    );

    return (
      <EuiForm component="div">
        <EuiTitle size="xs">
          <h3>{DETAILS_HEADER}</h3>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <EuiText size="s">
          <p>{DETAILS_HEADER_DESCRIPTION}</p>
        </EuiText>
        <EuiSpacer size="m" />

        <EuiFormRow
          label={NAME_LABEL}
          isInvalid={visited.name && !!Object.keys(errorsRef.current.name).length}
          error={Object.values(errorsRef.current.name)}
          fullWidth
        >
          <EuiFieldText
            name="name"
            value={item.name}
            onChange={handleOnNameChange}
            onBlur={handleOnNameBlur}
            required={visited.name}
            maxLength={256}
            data-test-subj={BLOCK_LIST_NAME_TEST_ID}
            fullWidth
          />
        </EuiFormRow>
        <EuiFormRow label={DESCRIPTION_LABEL} fullWidth>
          <EuiTextArea
            name="description"
            value={item.description}
            onChange={handleOnDescriptionChange}
            data-test-subj={BLOCK_LIST_DESCRIPTION_TEST_ID}
            fullWidth
            compressed
            maxLength={256}
          />
        </EuiFormRow>
        <EuiHorizontalRule />
        <EuiTitle size="xs">
          <h3>{CONDITIONS_HEADER}</h3>
        </EuiTitle>
        <EuiSpacer size="m" />

        <EuiFormRow fullWidth>
          <EuiFlexGroup gutterSize="s">
            <EuiFlexItem grow={2}>
              <EuiFormRow label={FIELD_LABEL} fullWidth>
                <EuiFieldText name="field" prepend="Hash" value="sha256, sha1 or md5" readOnly />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem grow={1}>
              <EuiFormRow label={OPERATOR_LABEL} fullWidth>
                <EuiFieldText name="operator" value={isOneOfOperator.message} readOnly />
              </EuiFormRow>
            </EuiFlexItem>
            <EuiFlexItem grow={2} />
          </EuiFlexGroup>
        </EuiFormRow>
        <EuiFormRow label={VALUE_LABEL} fullWidth>
          <EuiFieldText name="value" value={indicatorFileHash} readOnly />
        </EuiFormRow>

        {isPlatinumPlus && (
          <>
            <EuiHorizontalRule />
            <EuiFormRow fullWidth>
              <EffectedPolicySelect
                isGlobal={isGlobal}
                isPlatinumPlus={isPlatinumPlus}
                selected={selectedPolicies}
                options={policies}
                onChange={handleOnPolicyChange}
                isLoading={policiesIsLoading}
                description={POLICY_SELECT_DESCRIPTION}
              />
            </EuiFormRow>
          </>
        )}
      </EuiForm>
    );
  }
);
