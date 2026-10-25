"""Local administrative grant. NEVER expose as an HTTP endpoint."""
import argparse
from app.core import identifier
from app.db import database

parser=argparse.ArgumentParser(description='Grant TEST_ONLY permissions to one actor for one project')
parser.add_argument('--tenant',required=True)
parser.add_argument('--project',required=True)
parser.add_argument('--actor',required=True)
parser.add_argument('--revoke',action='store_true')
a=parser.parse_args()
for name,value in [('tenant',a.tenant),('project',a.project),('actor',a.actor)]:identifier(value,name)
with database() as conn:
    for permission in ('READ_TEST','POST_TEST','REVERSE_TEST'):
        conn.execute('''
            INSERT INTO fame_finance.actor_grants
               (tenant_id,project_id,actor_id,permission,active)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (tenant_id,project_id,actor_id,permission)
            DO UPDATE SET active=EXCLUDED.active
        ''', (a.tenant,a.project,a.actor,permission,not a.revoke))
print(('REVOKED' if a.revoke else 'GRANTED')+' test-only actor permissions')
