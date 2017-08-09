/* !
 Copyright (C) 2017 Google Inc.
 Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
 */

(function (GGRC, can, _) {
  'use strict';

  var customAttributesType = {
    Text: 'input',
    'Rich Text': 'text',
    'Map:Person': 'person',
    Date: 'date',
    Input: 'input',
    Checkbox: 'checkbox',
    Dropdown: 'dropdown'
  };

  var CA_DD_REQUIRED_DEPS = {
    NONE: 0,
    COMMENT: 1,
    EVIDENCE: 2,
    COMMENT_AND_EVIDENCE: 3
  };

  /**
   * Util methods for custom attributes.
   */
  GGRC.Utils.CustomAttributes = (function () {
    /**
     * Return normalized Custom Attribute Type from Custom Attribute Definition
     * @param {String} type - String Custom Attribute Value from JSON
     * @return {String} - Normalized Custom Attribute Type
     */
    function getCustomAttributeType(type) {
      return customAttributesType[type] || 'input';
    }

    function isEmptyCustomAttribute(value, type, cav) {
      var result = false;
      var types = ['Text', 'Rich Text', 'Date', 'Checkbox', 'Dropdown',
        'Map:Person'];
      var options = {
        Checkbox: function (value) {
          return !value || value === '0';
        },
        'Rich Text': function (value) {
          value = GGRC.Utils.getPlainText(value);
          return _.isEmpty(value);
        },
        'Map:Person': function (value, cav) {
          // Special case, Map:Person has 'Person' value by default
          if (cav) {
            return !cav.attribute_object;
          }
          return _.isEmpty(value);
        }
      };
      if (value === undefined) {
        return true;
      }
      if (types.indexOf(type) > -1 && options[type]) {
        result = options[type](value, cav);
      } else if (types.indexOf(type) > -1) {
        result = _.isEmpty(value);
      }
      return result;
    }

    /**
     * Converts custom attribute value for UI controls.
     * @param {String} type - Custom attribute type
     * @param {Object} value - Custom attribute value
     * @param {Object} valueObj - Custom attribute object
     * @return {Object} Converted value
     */
    function convertFromCaValue(type, value, valueObj) {
      if (type === 'checkbox') {
        return value === '1';
      }

      if (type === 'input') {
        if (!value) {
          return null;
        }
        return value.trim();
      }

      if (type === 'person') {
        if (valueObj) {
          return valueObj.id;
        }
        return null;
      }

      if (type === 'dropdown') {
        if (value === null || value === undefined) {
          return '';
        }
      }
      return value;
    }

    function validateField(field, value) {
      var fieldValid;
      var hasMissingEvidence;
      var hasMissingComment;
      var hasMissingValue;
      var requiresEvidence;
      var requiresComment;
      var valCfg = field.validationConfig;
      var fieldValidationConf = valCfg && valCfg[value];
      var isMandatory = field.validation.mandatory;
      var errors = field.preconditions_failed || [];
      var type = field.attributeType || field.type;

      hasMissingValue = errors.indexOf('value') > -1;

      if (type === 'checkbox') {
        if (value === '1') {
          value = true;
        } else if (value === '0') {
          value = false;
        }

        return {
          validation: {
            show: isMandatory,
            valid: isMandatory ? !hasMissingValue && !!(value) : true,
            hasMissingInfo: false
          }
        };
      } else if (type !== 'dropdown') {
        return {
          validation: {
            show: isMandatory,
            valid: isMandatory ? !hasMissingValue && !!(value) : true,
            hasMissingInfo: false
          }
        };
      }

      requiresEvidence =
        fieldValidationConf === CA_DD_REQUIRED_DEPS.EVIDENCE ||
        fieldValidationConf === CA_DD_REQUIRED_DEPS.COMMENT_AND_EVIDENCE;

      requiresComment =
        fieldValidationConf === CA_DD_REQUIRED_DEPS.COMMENT ||
        fieldValidationConf === CA_DD_REQUIRED_DEPS.COMMENT_AND_EVIDENCE;

      hasMissingEvidence = requiresEvidence && errors.indexOf('evidence') > -1;
      hasMissingComment = requiresComment && errors.indexOf('comment') > -1;

      fieldValid = (value) ?
        !(hasMissingEvidence || hasMissingComment || hasMissingValue) :
        !isMandatory && !hasMissingValue;

      return {
        validation: {
          show: isMandatory || !!value,
          valid: fieldValid,
          hasMissingInfo: (hasMissingEvidence || hasMissingComment)
        },
        errorsMap: {
          evidence: hasMissingEvidence,
          comment: hasMissingComment
        }
      };
    }

    function findValueByDefinitionId(values, defId) {
      return values.find(function (v) {
        return v.custom_attribute_id === defId;
      });
    }

    /**
     * Custom Attributes specific parsing logic to simplify business logic of Custom Attributes
     * @param {Array} definitions - original list of Custom Attributes Definition
     * @param {Array} values - original list of Custom Attributes Values
     * @return {Array} Updated Custom attributes
     */
    function prepareCustomAttributes(definitions, values) {
      return definitions.map(function (def) {
        var valObj;
        var id = def.id;
        var options = (def.multi_choice_options || '').split(',');
        var optionsRequirements = (def.multi_choice_mandatory || '').split(',');
        var type = getCustomAttributeType(def.attribute_type);

        var base = {
          id: null,
          custom_attribute_id: id,
          attribute_value: null,
          attribute_object: null,
          validation: {
            show: false,
            mandatory: def.mandatory,
            valid: true
          },
          validationConfig: null,
          def: def,
          attributeType: type,
          preconditions_failed: [],
          errorsMap: {
            comment: false,
            evidence: false
          }
        };

        valObj = findValueByDefinitionId(values, id);

        if (type === 'dropdown') {
          base.validationConfig = options.reduce(function (conf, item, idx) {
            conf[item] = Number(optionsRequirements[idx]);
            return conf;
          }, {});
        }

        if (valObj) {
          _.merge(base, valObj);
          _.merge(base, validateField(base, base.attribute_value));
        }

        return base;
      });
    }

    /**
     * Converts value from UI controls back to CA value.
     * @param {String} type - Custom attribute type
     * @param {Object} value - Control value
     * @return {Object} Converted value
     */
    function convertToCaValue(type, value) {
      if (type === 'checkbox') {
        return value ? 1 : 0;
      }

      if (type === 'person') {
        if (value) {
          return 'Person:' + value;
        }
        return 'Person:None';
      }
      return value || null;
    }

    /**
     * Converts CA values array to form fields.
     * @param {can.List|undefined} customAttributeValues - Custom attributes values
     * @return {Array} From fields array
     */
    function convertValuesToFormFields(customAttributeValues) {
      return (customAttributeValues || new can.List([]))
        .map(convertToEditableField);
    }

    function convertToFormViewField(attr) {
      var options = attr.def.multi_choice_options;
      return {
        type: attr.attributeType,
        id: attr.def.id,
        value: convertFromCaValue(
          attr.attributeType,
          attr.attribute_value,
          attr.attribute_object
        ),
        title: attr.def.title,
        placeholder: attr.def.placeholder,
        options: options &&
        typeof options === 'string' ?
          options.split(',') : [],
        helptext: attr.def.helptext
      };
    }

    function convertToEditableField(attr) {
      var options = attr.def.multi_choice_options;
      return {
        type: attr.attributeType,
        id: attr.def.id,
        value: convertFromCaValue(
          attr.attributeType,
          attr.attribute_value,
          attr.attribute_object
        ),
        title: attr.def.title,
        placeholder: attr.def.placeholder,
        options: options &&
        typeof options === 'string' ?
          options.split(',') : [],
        helptext: attr.def.helptext,
        validation: attr.validation.attr(),
        validationConfig: attr.validationConfig,
        preconditions_failed: attr.preconditions_failed,
        errorsMap: attr.errorsMap.attr(),
        valueId: can.compute(function () {
          return attr.attr('id');
        })
      };
    }

    function getAttributes(values, onlyLocal) {
      return (values || []).filter(function (value) {
        return !onlyLocal ?
        value.def.definition_id === null :
        value.def.definition_id !== null;
      });
    }
    function updateCustomAttributeValue(ca, value) {
      var id;
      if (ca.attr('attributeType') === 'person') {
        id = value || null;
        ca.attr('attribute_value', 'Person');
        ca.attr('attribute_object', {id: id, type: 'Person'});
      } else {
        ca.attr('attribute_value',
          GGRC.Utils.CustomAttributes.convertToCaValue(
            ca.attr('attributeType'), value)
        );
      }
    }

    function applyChangesToCustomAttributeValue(values, changes) {
      var caValues = can.makeArray(values);
      can.Map.keys(changes).forEach(function (fieldId) {
        var caValue =
          caValues
            .find(function (item) {
              return item.def.id === Number(fieldId);
            });
        if (!caValue) {
          console.error('Corrupted Date: ', caValues);
          return;
        }
        updateCustomAttributeValue(caValue, changes[fieldId]);
      });
    }
    return {
      CA_DD_REQUIRED_DEPS: CA_DD_REQUIRED_DEPS,
      convertFromCaValue: convertFromCaValue,
      validateField: validateField,
      convertToCaValue: convertToCaValue,
      convertValuesToFormFields: convertValuesToFormFields,
      prepareCustomAttributes: prepareCustomAttributes,
      isEmptyCustomAttribute: isEmptyCustomAttribute,
      getAttributes: getAttributes,
      getCustomAttributeType: getCustomAttributeType,
      convertToFormViewField: convertToFormViewField,
      applyChangesToCustomAttributeValue: applyChangesToCustomAttributeValue
    };
  })();
})(window.GGRC, window.can, window._);
