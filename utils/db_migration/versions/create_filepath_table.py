# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Create filepath table

Revision ID: 25cb9090c7f9
Revises: cd31654d187
Create Date: 2019-02-24 02:28:43.734531

"""

# revision identifiers, used by Alembic.
revision = '25cb9090c7f9'
down_revision = 'cd31654d187'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('filepaths',
                    sa.Column('task_id',sa.Integer, primary_key=True),
                    sa.Column('file_path', sa.String(255), primary_key=True))


def downgrade():
    op.drop_table('filepaths')
