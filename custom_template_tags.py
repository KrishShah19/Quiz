# Create a custom_template_tags.py file in one of your app's directories
from django import template

register = template.Library()

@register.filter
def has_admin_role(user):
    return user.role == 'admin'
