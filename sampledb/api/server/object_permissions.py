# coding: utf-8
"""
RESTful API for SampleDB
"""

import flask

from .authentication import object_permissions_required, multi_auth
from ..utils import Resource, ResponseData, prepare_object_permissions
from ...logic import users, groups, projects, errors, object_permissions, objects
from ...models import Permissions

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


class ObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        return prepare_object_permissions(
            object_permissions.get_all_object_permissions(object_id=object_id)
        ), 200

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int) -> ResponseData:
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, dict):
            return {
                "message": "JSON dict body required"
            }, 400

        # User-Permissions
        if (user_perms := request_json.get("users")) is not None:
            for user_id, permission in user_perms.items():
                try:
                    users.check_user_exists(user_id)
                except errors.UserDoesNotExistError:
                    return {
                        "message": f"user {user_id} does not exist"
                    }, 404
                if not isinstance(permission, str):
                    return {
                        "message": "JSON string for permission required"
                    }, 400
                try:
                    permissions = Permissions.from_name(permission)
                except ValueError:
                    return {
                        "message": f"Permissions name for user {user_id} required"
                    }, 400
                object_permissions.set_user_object_permissions(
                    object_id,
                    user_id,
                    permissions,
                )

        # Group-Permissions
        if (group_perms := request_json.get("basic_groups")) is not None:
            for group_id, permission in group_perms.items():
                try:
                    groups.get_group(group_id)
                except errors.GroupDoesNotExistError:
                    return {
                        "message": f"group {group_id} does not exist"
                    }, 404
                if not isinstance(permission, str):
                    return {
                        "message": "JSON string for permission required"
                    }, 400
                try:
                    permissions = Permissions.from_name(permission)
                except ValueError:
                    return {
                        "message": f"Permissions name for group {group_id} required"
                    }, 400
                object_permissions.set_group_object_permissions(
                    object_id,
                    group_id,
                    permissions,
                )

        # Project-Permissions
        if (project_perms := request_json.get("projects")) is not None:
            for project_id, permission in project_perms.items():
                try:
                    projects.get_project(project_id)
                except errors.ProjectDoesNotExistError:
                    return {
                        "message": f"project {project_id} does not exist"
                    }, 404
                if not isinstance(permission, str):
                    return {
                        "message": "JSON string for permission required"
                    }, 400
                try:
                    permissions = Permissions.from_name(permission)
                except ValueError:
                    return {
                        "message": f"Permissions name for project {project_id} required"
                    }, 400
                object_permissions.set_project_object_permissions(
                    object_id,
                    project_id,
                    permissions,
                )

        # Authenticated
        if (permission := request_json.get("authenticated")) is not None:
            if not isinstance(permission, str):
                return {
                    "message": "JSON string for permission required"
                }, 400
            permissions = Permissions.from_name(permission)
            if permissions not in {Permissions.NONE, Permissions.READ}:
                return {
                    "message": 'expected "none" or "read"'
                }, 400
            object_permissions.set_object_permissions_for_all_users(
                object_id=object_id,
                permissions=permissions,
            )

        # Anonymous
        if (permission := request_json.get("anonymous")) is not None:
            if permission is not None and not flask.current_app.config['ENABLE_ANONYMOUS_USERS']:
                return {
                    "message": "anonymous users are disabled"
                }, 400
            if not isinstance(permission, str):
                return {
                    "message": "JSON string for permission required"
                }, 400
            permissions = Permissions.from_name(permission)
            if permissions not in {Permissions.NONE, Permissions.READ}:
                return {
                    "message": 'expected "none" or "read"'
                }, 400
            object_permissions.set_object_permissions_for_anonymous_users(
                object_id=object_id,
                permissions=permissions,
            )
        return prepare_object_permissions(
            object_permissions.get_all_object_permissions(object_id=object_id)
        ), 200


class CopyObjectsPermissions(Resource):
    @multi_auth.login_required
    def post(self):
        user_id = flask.g.user.id
        user = users.get_user(user_id=user_id)
        if user.is_readonly:
            return {
                "message": "No permission to copy object's permissions"
            }, 403
        request_json = flask.request.get_json(force=True)
        if isinstance(request_json, dict):
            request_json = [request_json]
        elif not isinstance(request_json, list):
            return {
                "message": "JSON list or dict body required"
            }, 400
        try:
            for item in request_json:
                # Validating all incoming object ids before changing any permission
                for object_id in [item["source"], item["target"]]:
                    object_id = int(object_id)
                    try:
                        objects.check_object_exists(object_id)
                    except errors.ObjectDoesNotExistError:
                        return {
                            "message": f"object {object_id} does not exist"
                        }, 404

                # Assure highest permission for source object is atleast READ
                # to view object's permission
                if max(
                    object_permissions.get_object_permissions_for_all_users(item["source"]),
                    object_permissions.get_user_object_permissions(
                        object_id=item["source"],
                        user_id=user_id,
                    )
                ) < Permissions.READ:
                    return {
                        "message": f"missing object permission for source object {item["source"]}"
                    }, 403

                # Assure highest permission for target object is atleast GRANT
                # to allow permission-manipulation
                if object_permissions.get_user_object_permissions(
                    object_id=item["target"],
                    user_id=user_id,
                ) < Permissions.GRANT:
                    return {
                        "message": f"missing object permission for target object {item["target"]}"
                    }, 403

        except ValueError:
            return {
                "message": "body parameters 'source' and 'target' required to be object-ids"
            }, 400
        except KeyError:
            return {
                "message": "JSON dict body required 'source' and 'target' key"
            }, 400

        for item in request_json:
            source_object = item["source"]
            target_object = item["target"]
            object_permissions.copy_permissions(
                source_object_id=source_object,
                target_object_id=target_object,
            )
        return "", 200


class UserObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int, user_id: int) -> ResponseData:
        include_instrument_responsible_users = 'include_instrument_responsible_users' in flask.request.args
        include_groups = 'include_groups' in flask.request.args
        include_projects = 'include_projects' in flask.request.args
        include_admins = 'include_admins' in flask.request.args
        permissions = object_permissions.get_object_permissions_for_users(
            object_id=object_id,
            include_instrument_responsible_users=include_instrument_responsible_users,
            include_groups=include_groups,
            include_projects=include_projects,
            include_admin_permissions=include_admins
        ).get(user_id, Permissions.NONE)
        if permissions == Permissions.NONE:
            try:
                users.check_user_exists(user_id)
            except errors.UserDoesNotExistError:
                return {
                    "message": f"user {user_id} does not exist"
                }, 404
        return permissions.name.lower()

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int, user_id: int) -> ResponseData:
        try:
            users.check_user_exists(user_id)
        except errors.UserDoesNotExistError:
            return {
                "message": f"user {user_id} does not exist"
            }, 404
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, str):
            return {
                "message": "JSON string body required"
            }, 400
        try:
            permissions = Permissions.from_name(request_json)
        except ValueError:
            return {
                "message": "Permissions name required"
            }, 400
        object_permissions.set_user_object_permissions(object_id, user_id, permissions)
        return permissions.name.lower(), 200


class UsersObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        include_instrument_responsible_users = 'include_instrument_responsible_users' in flask.request.args
        include_groups = 'include_groups' in flask.request.args
        include_projects = 'include_projects' in flask.request.args
        include_admins = 'include_admins' in flask.request.args
        permissions = object_permissions.get_object_permissions_for_users(
            object_id=object_id,
            include_instrument_responsible_users=include_instrument_responsible_users,
            include_groups=include_groups,
            include_projects=include_projects,
            include_admin_permissions=include_admins
        )
        return {
            user_id: permissions.name.lower()
            for user_id, permissions in permissions.items()
        }, 200


class GroupObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int, group_id: int) -> ResponseData:
        include_projects = 'include_projects' in flask.request.args
        permissions = object_permissions.get_object_permissions_for_groups(
            object_id=object_id,
            include_projects=include_projects
        ).get(group_id, Permissions.NONE)
        if permissions == Permissions.NONE:
            try:
                groups.get_group(group_id)
            except errors.GroupDoesNotExistError:
                return {
                    "message": f"group {group_id} does not exist"
                }, 404
        return permissions.name.lower()

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int, group_id: int) -> ResponseData:
        try:
            groups.get_group(group_id)
        except errors.GroupDoesNotExistError:
            return {
                "message": f"group {group_id} does not exist"
            }, 404
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, str):
            return {
                "message": "JSON string body required"
            }, 400
        try:
            permissions = Permissions.from_name(request_json)
        except ValueError:
            return {
                "message": "Permissions name required"
            }, 400
        object_permissions.set_group_object_permissions(object_id, group_id, permissions)
        return permissions.name.lower(), 200


class GroupsObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        include_projects = 'include_projects' in flask.request.args
        permissions = object_permissions.get_object_permissions_for_groups(
            object_id=object_id,
            include_projects=include_projects
        )
        return {
            group_id: permissions.name.lower()
            for group_id, permissions in permissions.items()
        }, 200


class ProjectObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int, project_id: int) -> ResponseData:
        permissions = object_permissions.get_object_permissions_for_projects(
            object_id=object_id
        ).get(project_id, Permissions.NONE)
        if permissions == Permissions.NONE:
            try:
                projects.get_project(project_id)
            except errors.ProjectDoesNotExistError:
                return {
                    "message": f"project {project_id} does not exist"
                }, 404
        return permissions.name.lower()

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int, project_id: int) -> ResponseData:
        try:
            projects.get_project(project_id)
        except errors.ProjectDoesNotExistError:
            return {
                "message": f"project {project_id} does not exist"
            }, 404
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, str):
            return {
                "message": "JSON string body required"
            }, 400
        try:
            permissions = Permissions.from_name(request_json)
        except ValueError:
            return {
                "message": "Permissions name required"
            }, 400
        object_permissions.set_project_object_permissions(object_id, project_id, permissions)
        return permissions.name.lower(), 200


class ProjectsObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        permissions = object_permissions.get_object_permissions_for_projects(
            object_id=object_id,
        )
        return {
            project_id: permissions.name.lower()
            for project_id, permissions in permissions.items()
        }, 200


class PublicObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        is_public = Permissions.READ in object_permissions.get_object_permissions_for_all_users(
            object_id=object_id
        )
        return is_public, 200

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int) -> ResponseData:
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, bool):
            return {
                "message": "JSON boolean body required"
            }, 400
        is_public = bool(request_json)
        object_permissions.set_object_permissions_for_all_users(
            object_id=object_id,
            permissions=Permissions.READ if is_public else Permissions.NONE
        )
        return is_public, 200


class AuthenticatedUserObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        permissions = object_permissions.get_object_permissions_for_all_users(
            object_id=object_id
        )
        return permissions.name.lower(), 200

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int) -> ResponseData:
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, str):
            return {
                "message": "JSON string body required"
            }, 400
        try:
            permissions = Permissions.from_name(request_json)
            if permissions not in {Permissions.NONE, Permissions.READ}:
                raise ValueError("invalid permissions level")
        except ValueError:
            return {
                "message": 'expected "none" or "read"'
            }, 400
        object_permissions.set_object_permissions_for_all_users(
            object_id=object_id,
            permissions=permissions
        )
        return permissions.name.lower(), 200


class AnonymousUserObjectPermissions(Resource):
    @object_permissions_required(Permissions.READ)
    def get(self, object_id: int) -> ResponseData:
        if not flask.current_app.config['ENABLE_ANONYMOUS_USERS']:
            return {
                "message": "anonymous users are disabled"
            }, 400
        permissions = object_permissions.get_object_permissions_for_anonymous_users(
            object_id=object_id
        )
        return permissions.name.lower(), 200

    @object_permissions_required(Permissions.GRANT)
    def put(self, object_id: int) -> ResponseData:
        if not flask.current_app.config['ENABLE_ANONYMOUS_USERS']:
            return {
                "message": "anonymous users are disabled"
            }, 400
        request_json = flask.request.get_json(force=True)
        if not isinstance(request_json, str):
            return {
                "message": "JSON string body required"
            }, 400
        try:
            permissions = Permissions.from_name(request_json)
            if permissions not in {Permissions.NONE, Permissions.READ}:
                raise ValueError("invalid permissions level")
        except ValueError:
            return {
                "message": 'expected "none" or "read"'
            }, 400
        object_permissions.set_object_permissions_for_anonymous_users(
            object_id=object_id,
            permissions=permissions
        )
        return permissions.name.lower(), 200
