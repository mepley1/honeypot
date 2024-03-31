#!/usr/bin/env python3

""" *******************************************************************************************
    This script updates the null `contenttype` field of each row in the database.
    Extract the Content-Type header from headers_json, and insert into the `contenttype` column.
    Archiving since I only need it once, to update about 21k rows I had already collected
    before I started saving Content-Type to its own column.
    *******************************************************************************************
"""

import sqlite3

requests_db = "bots.db"

def update_row(request_id):
    print('Begin row: ', request_id)

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Select the single request from the db, by it's ID
        sql_query = "SELECT JSON_EXTRACT(headers_json, '$.Content-Type') FROM bots WHERE id = ?;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        try:
            content_type = c.fetchone()[0]
            print(f'Content-Type: {content_type}')
        except TypeError as e:
            print('Bad request; ID doesn\'t exist.')
            return('ID Doesnt exist.')

        #If content-type is None, replace it with empty string instead.
        #The data table on stats.html is too cluttered with 'None' everywhere, prefer empty space for readability.
        if content_type is None:
            print('No content-type declared; replacing with empty string.')
            content_type = ''

        # Now update the row
        print('updating row...')

        # Update the row, where id = id
        sql_query = '''
            UPDATE bots
            SET contenttype = ?
            WHERE id = ?;
            '''
        data_tuple = (content_type, request_id,)
        c.execute(sql_query, data_tuple)
        c.close()
    conn.close()

    print('finished.\n')

if __name__ == '__main__':
    print('running...')
    for i in range(1, 20900):
        print(f'\n*** UPDATE ROW: {i} ***\n')
        update_row(i)
    print('JOB COMPLETE\n')
