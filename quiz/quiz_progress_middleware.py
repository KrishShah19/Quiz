import logging
from django.utils import timezone
from django.http import QueryDict  # Import QueryDict
from .models import QuizProgress

logger = logging.getLogger(__name__)

class QuizProgressMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is leaving the quiz page
        if '/python_quiz/' in request.path and request.method == 'GET':
            logger.info('User left the quiz page')  # Add this line to log a message

            # Replace '/python_quiz/' with the actual URL path for your quiz page
            # Save quiz progress to the database
            user = request.user
            query_params = QueryDict(request.META['QUERY_STRING'])  # Use QueryDict to parse query parameters
            category_id = query_params.get('category_id', None)  # Get the 'category_id' parameter
            timer_state = request.session.get('timer_state', 0)  # Retrieve timer state from session
            last_activity = timezone.now()

            if category_id is not None:
                QuizProgress.objects.update_or_create(
                    user=user,
                    category_id=category_id,
                    defaults={'timer_state': timer_state, 'last_activity': last_activity}
                )

        response = self.get_response(request)
        return response
