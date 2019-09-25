.. _users:

Users
=====

.. _authentication:

Authentication
--------------

Employees at PGI or JCNS have a **LDAP username**, which they can use with the corresponding password to sign in. An account will be created automatically.

Guests at a facility using |service_name| should ask another user of |service_name| for an **invitation**, e.g. the scientist responsible for the instrument they will be using. Once the guest has confirmed their email address by clicking the confirmation link in the invitation email, they can then set a password for their new |service_name| account.

.. figure:: ../static/img/generated/guest_invitation.png
    :scale: 50 %
    :alt: Guest Invitation Form

    Guest Invitation Form

Users can find the invitation form at |service_invitation_url|.

.. _preferences:

Preferences
-----------

Users can edit their preferences by clicking on their name in the top right corner and selecting preferences.

The preferences are split into the following sections:

User Information
````````````````

Users can update their user name displayed on |service_name|, e.g. in the event of a marriage. They can also change their email address, which will be updated once the new address has been confirmed.

Authentication Methods
``````````````````````

Users can have multiple ways of signing in to |service_name|, for example using their LDAP account or using an email address. This section of the user preferences can be used to add, modify or remove such authentication methods, e.g. for users leaving their institute but still requiring access to their sample data.

Default Permissions
```````````````````

To automatically set permissions for future objects, users can set **default permissions** in their preferences. These will be applied whenever an object like a sample or measurement is created afterwards.

For more information, see :ref:`default_permissions`.

Activity Log
------------

Users can view their or other users' activities in |service_name|, as far as these are related to objects they have permissions for. This can be useful, e.g. for quickly finding objects they've created.

.. _notifications:

Notifications
-------------

Users will receive notifications whenever they need to be informed about an activity on |service_name|. Whenever a user has unread notifications, a bell with the number of unread notifications is shown in the navigation bar.

.. figure:: ../static/img/generated/unread_notification_icon.png
    :scale: 50 %
    :alt: Unread Notification Icon

    Unread Notification Icon

Bot Users
---------

Tasks like object creation can be automated by using the :ref:`HTTP API <http_api>`. When this is done in connection to an instrument or a facility instead of an individual user, it may be better to create a dedicated user account solely for this purpose.