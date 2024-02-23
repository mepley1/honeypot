#!/usr/bin/env python3

""" *******************************************************************************************
    This script updates the null headers_json field of each request in the database, 
    converting to JSON from the old headers field which was saved as a 
    string of a dictionary (i.e. str(dict(headers)).
    Create a dict by calling ast.literal_eval() on the dict string, then convert to JSON and 
    insert into headers_json field. 
    Archiving since I only needed it once, to update about 22K rows I had already collected.
    *******************************************************************************************
"""

import sqlite3
import ast
import json

requests_db = "bots.db"

def update_row(request_id):
    print('\n*Begin row: ', request_id)

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Select the single request from the db, by it's ID
        sql_query = "SELECT headers FROM bots WHERE id = ?;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        try:
            saved_headers = c.fetchone()[0]
        except TypeError as e:
            print('Bad request; ID doesn\'t exist.')
            return('ID Doesnt exist.')
        c.close()
    conn.close()

    #Recreate the dictionary from the saved data.
    recreated_dictionary = ast.literal_eval(saved_headers)

    # Create a JSON string from it
    headers_json = json.dumps(recreated_dictionary)
    print('JSON headers: \n', headers_json)

    #validate JSON
    '''print('attempt to validate...')
    pass
    print('results: \n', results)'''

    #input('press enter to continue...\n')

    # Now update the row
    print('updating row...')

    with sqlite3.connect(requests_db) as conn:
        c = conn.cursor()
        # Update the row, where id = id
        sql_query = """
            UPDATE bots
            SET headers_json = ?
            WHERE id = ?;
            """
        data_tuple = (headers_json, request_id,)
        c.execute(sql_query, data_tuple)
        c.close()
    conn.close()

    print('finished.\n')

if __name__ == '__main__':
    print('running...')
    for i in range(20, 21735):
        print(f'\n***UPDATING ROW: ***\n {i}')
        update_row(i)
