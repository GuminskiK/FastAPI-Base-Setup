import re

with open('backend/app/core/exceptions/exceptions.py', 'r') as f:
    content = f.read()

content = re.sub(
    r'super\(\)\.__init__\(\s*status_code=status\.HTTP_404_NOT_FOUND,\s*detail=f"\{resource_name\} not found"\s*\)',
    r'super().__init__(resource_name=resource_name)',
    content
)

content = re.sub(
    r'super\(\)\.__init__\(status_code=status\.HTTP_403_FORBIDDEN,\s*detail=(.*?)\)',
    r'super().__init__(detail=\1)',
    content
)

content = re.sub(
    r'super\(\)\.__init__\(status_code=status\.HTTP_400_BAD_REQUEST,\s*detail=(.*?)\)',
    r'super().__init__(detail=\1)',
    content
)

content = re.sub(
    r'super\(\)\.__init__\(status_code=status\.HTTP_500_INTERNAL_SERVER_ERROR,\s*detail=(.*?)\)',
    r'super().__init__(detail=\1)',
    content
)

with open('backend/app/core/exceptions/exceptions.py', 'w') as f:
    f.write(content)
