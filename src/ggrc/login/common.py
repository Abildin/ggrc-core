# Copyright (C) 2019 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Handle the interface to GGRC models for all login methods.
"""

import logging

import flask
from werkzeug import exceptions

from ggrc import db, settings

from ggrc.models import all_models
from ggrc.utils.log_event import log_event
from ggrc.utils.user_generator import (
    find_or_create_ext_app_user, is_external_app_user_email,
    parse_user_credentials, find_or_create_user_by_email
)


logger = logging.getLogger(__name__)


def get_next_url(request, default_url):
  """Returns next url from requres or default url if it's not found."""
  if 'next' in request.args:
    next_url = request.args['next']
    return next_url
  return default_url


def commit_user_and_role(user):
  """Commits and flushes user and its role after the login."""
  db_user, db_role = None, None
  if hasattr(flask.g, "user_cache"):
    db_user = flask.g.user_cache.get(user.email, None)
  if hasattr(flask.g, "user_creator_roles_cache"):
    db_role = flask.g.user_creator_roles_cache.get(user.email, None)
  if db_user or db_role:
    db.session.flush()
    if db_user:
      log_event(db.session, db_user, db_user.id, flush=False)
    elif db_role:
      # log_event of user includes event of role creation.
      # if no user in cache, then it was created before but has no role.
      log_event(db.session, db_role, user.id, flush=False)
    db.session.commit()


def check_appengine_appid(request):
  """Check if appengine app ID in whitelist."""
  inbound_appid = request.headers.get("X-Appengine-Inbound-Appid")

  if not inbound_appid:
    # don't check X-GGRC-user if the request doesn't come from another app
    return None

  if inbound_appid not in settings.ALLOWED_QUERYAPI_APP_IDS:
    # by default, we don't allow incoming app2app connections from
    # non-whitelisted apps
    raise exceptions.BadRequest("X-Appengine-Inbound-Appid header contains "
                                "untrusted application id: {}"
                                .format(inbound_appid))

  return inbound_appid


def get_ggrc_user(request, mandatory):
  """Find user from credentials in "X-GGRC-user" header."""
  credentials = parse_user_credentials(request, "X-GGRC-USER",
                                       mandatory=mandatory)

  if not credentials:
    return None

  if is_external_app_user_email(credentials.email):
    # External Application User should be created if doesn't exist.
    user = get_external_app_user(request)
  else:
    user = all_models.Person.query.filter_by(email=credentials.email).one()

  if not user:
    raise exceptions.BadRequest("No user with such credentials: %s" %
                                credentials.email)

  return user


def get_external_app_user(request):
  """Find or create external user from credentials in "X-GGRC-USER" header."""
  app_user = find_or_create_ext_app_user()

  if app_user.id is None:
    db.session.commit()

  credentials = parse_user_credentials(request, "X-EXTERNAL-USER",
                                       mandatory=False)

  if credentials:
    # Create external app user provided in X-EXTERNAL-USER header.
    try:
      create_external_user(app_user, credentials.email, credentials.name)
    except exceptions.BadRequest as exp:
      logger.error("Creation of external user has failed. %s", exp.message)
      raise

  return app_user


def create_external_user(app_user, email, name):
  """Create external user."""
  user = find_or_create_user_by_email(email, name, modifier=app_user.id)

  if user and user.id is None:
    db.session.flush()
    log_event(db.session, user, app_user.id)
    db.session.commit()

  return user
