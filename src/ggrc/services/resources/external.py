# Copyright (C) 2019 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""External service models API resource."""

from werkzeug.exceptions import Forbidden, MethodNotAllowed

from ggrc import db, utils
from ggrc.login import get_current_user, is_external_app_user
from ggrc.login.common import create_external_user
from ggrc.services import common
from ggrc.utils.user_generator import parse_user_credentials


class ExternalResource(common.Resource):
  """Resource handler for external service models."""

  def post(self, *args, **kwargs):
    """POST operation handler."""
    del args, kwargs
    raise MethodNotAllowed()

  def collection_post(self):
    """Prevent creation of object for internal users."""
    if not is_external_app_user():
      raise Forbidden()

    return super(ExternalResource, self).collection_post()

  @utils.validate_mimetype("application/json")
  def put(self, *args, **kwargs):   # pylint:disable=arguments-differ
    """Prevent update of object for internal users."""
    if not is_external_app_user():
      raise Forbidden()

    return super(ExternalResource, self).put(*args, **kwargs)

  def patch(self, *args, **kwargs):   # pylint:disable=arguments-differ
    """PATCH operation handler."""
    del args, kwargs
    raise MethodNotAllowed()

  def delete(self, *args, **kwargs):  # pylint:disable=arguments-differ
    """Prevent update of object for internal users."""
    if not is_external_app_user():
      raise Forbidden()

    return super(ExternalResource, self).delete(*args, **kwargs)

  def validate_headers_for_put_or_delete(self, obj):
    """Skip ETAG checking for external resources."""
    return None

  def add_modified_object_to_session(self, obj):
    """Update modification metadata and add object to session."""
    obj.modified_by = self.get_external_user()

    db.session.add(obj)

  def get_external_user(self):
    """Get current external user from request header."""
    # In current implementation, "get_current_user" makes request to
    # integration service if we call with use_external_user = True.
    # We decided to remove HR API confirmation phase, so to prevent
    # request sending we call it with use_external_user = False.
    user = get_current_user(use_external_user=False)

    if "X-EXTERNAL-USER" in self.request.headers:
      credentials = parse_user_credentials(self.request, "X-EXTERNAL-USER",
                                           mandatory=True)

      user = create_external_user(user, credentials.email, credentials.name)

    return user
