# Copyright (C) 2019 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Module with common validators for GGRC."""

from werkzeug import exceptions


# pylint: disable=unused-argument
def validate_object_type_ggrcq(mapper, content, target):
  """Validate object_type actions for GGRCQ."""
  from ggrc import login as login_module
  from ggrc.models import get_model
  from ggrc.models.mixins import synchronizable

  model = get_model(target.object_type)
  user = login_module.get_current_user(False)

  if target.internal or not user or user.is_anonymous():
    return

  should_prevent = all([
      issubclass(model, synchronizable.Synchronizable),
      not login_module.is_external_app_user()
  ])

  if should_prevent:
    raise exceptions.MethodNotAllowed()


# pylint: disable=unused-argument
def validate_definition_type_ggrcq(mapper, content, target):
  """Validate GGRCQ action for object with definition_type."""
  from ggrc import login as login_module
  from ggrc.models import get_model
  from ggrc.models.mixins import synchronizable

  model = get_model(target.definition_type)
  user = login_module.get_current_user(False)

  if not user or user.is_anonymous():
    return

  should_prevent = all([
      issubclass(model, synchronizable.Synchronizable),
      not login_module.is_external_app_user()
  ])

  if should_prevent:
    raise exceptions.MethodNotAllowed()
