
import enum

from hubub_common.exceptions import RecordNotFound

from .base import BaseModel, ModelSchema, fields

from .db import Session

import sqlalchemy as sa
from sqlalchemy import (
        Index, DDL, event, FetchedValue, func, Column, false,
        Integer, ForeignKey, String, DateTime, UniqueConstraint, Boolean
    )
from sqlalchemy.orm import relationship


class AccountStatus(enum.Enum):
    active = 1
    disabled = 2


class Account(BaseModel):
    __tablename__ = 'account'
    id = sa.Column(sa.String, primary_key=True, server_default=FetchedValue())
    account_status = sa.Column(
        sa.Enum(*[value for value, _ in AccountStatus.__members__.items()], name='account_status_enum'))
    label = sa.Column(sa.String)
    name = sa.Column(sa.String, unique=True, nullable=False)
    secret = sa.Column(sa.String)

    account_group_id = sa.Column(sa.Integer, sa.ForeignKey('account_group.id'))

    tags = relationship("AccountTag", backref="account", uselist=True, lazy="dynamic")
    users = relationship('User', backref='account', uselist=True, lazy='dynamic')

    push_notification_certificate = relationship("PushNotificationCertificate")
    push_notification_certificate_id = sa.Column(sa.Integer, sa.ForeignKey('push_notification_certificate.id'))

    created_at = sa.Column(sa.DateTime, server_default=func.now())
    updated_at = sa.Column(sa.DateTime, server_default=func.now())
    deleted_at = sa.Column(sa.DateTime, nullable=True, server_default=None)

    async def get_account_by_id(conn, account_id):
        result = await conn.execute(
            sa.session.select().where(sa.session.c.id == account_id))
        account_record = await result.first()
        if not account_record:
            raise RecordNotFound()

        return account_record


class AccountSchema(ModelSchema):
    id = fields.String(dump_only=True)
    account_status = fields.Integer(required=False)
    label = fields.String(required=False)
    name = fields.String(required=True)
    secret = fields.String(required=False)
    account_group_id = fields.Integer(required=False)

    tags = fields.Nested('AccountTagSchema', many=True, required=False, missing=[])
    users = fields.Nested('UserSchema', many=True, required=False, missing=[])

    created_at = fields.DateTime(required=False)
    updated_at = fields.DateTime(required=False)
    deleted_at = fields.DateTime(required=False)

    class Meta:
        model = Account
        sqla_session = Session
        strict = False


id_url62_trigger_function = DDL("""

        CREATE EXTENSION IF NOT EXISTS "pgcrypto";

        DROP TRIGGER IF EXISTS trigger_gen_id ON account;
        DROP FUNCTION IF EXISTS unique_short_id();

        CREATE OR REPLACE FUNCTION unique_short_id()
        RETURNS TRIGGER AS $$

         -- Declare the variables we'll be using.
        DECLARE
          key TEXT;
          qry TEXT;
          found TEXT;
        BEGIN

          -- generate the first part of a query as a string with safely
          -- escaped table name, using || to concat the parts
          qry := 'SELECT id FROM ' || quote_ident(TG_TABLE_NAME) || ' WHERE id=';

          -- This loop will probably only run once per call until we've generated
          -- millions of ids.
          LOOP

            -- Generate our string bytes and re-encode as a url64 string.
            key := encode(gen_random_bytes(12), 'base64');

            -- Base64 encoding not contains 2 URL unsafe characters and get url62.
            -- Replace it
            key := replace(key, '/', '0'); -- url safe replacement
            key := replace(key, '+', '0'); -- url safe replacement

            -- Concat the generated key (safely quoted) with the id query
            -- and run it.
            EXECUTE qry || quote_literal(key) INTO found;

            -- Check to see if found is NULL.
            -- If we checked to see if found = NULL it would always be FALSE
            -- because (NULL = NULL) is always FALSE.
            IF found IS NULL THEN

              -- If we didn't find a collision then leave the LOOP.
              EXIT;
            END IF;

            -- We haven't EXITed yet, so return to the top of the LOOP
            -- and try again.
          END LOOP;

          -- NEW and OLD are available in TRIGGER PROCEDURES.
          -- NEW is the mutated row that will actually be INSERTed.
          -- We're replacing id, regardless of what it was before
          NEW.id = key;

          -- The RECORD returned here is what will actually be INSERTed,
          -- or what the next trigger will get if there is one.
          RETURN NEW;
        END;
        $$ language 'plpgsql';

        CREATE TRIGGER trigger_gen_id
        BEFORE INSERT
        ON account
        FOR EACH ROW
        EXECUTE PROCEDURE unique_short_id();
    """)

event.listen(Account.__table__, 'after_create', id_url62_trigger_function.execute_if(dialect='postgresql'))
