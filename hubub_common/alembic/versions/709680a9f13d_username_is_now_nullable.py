"""username is now nullable

Revision ID: 709680a9f13d
Revises: 69916cffae82
Create Date: 2021-02-24 13:31:48.297923

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '709680a9f13d'
down_revision = '69916cffae82'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'username',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'username',
               existing_type=sa.VARCHAR(),
               nullable=False)
    # ### end Alembic commands ###
