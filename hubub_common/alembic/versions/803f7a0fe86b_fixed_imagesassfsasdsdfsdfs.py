"""fixed imagesassfsasdsdfsdfs

Revision ID: 803f7a0fe86b
Revises: 2491c5a09a8c
Create Date: 2021-03-08 16:31:57.665409

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '803f7a0fe86b'
down_revision = '2491c5a09a8c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'image', ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'image', type_='unique')
    # ### end Alembic commands ###
