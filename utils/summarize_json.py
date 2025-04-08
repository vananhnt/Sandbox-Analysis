import json

json_data = '{"customer_id":2947, "order_id":4923, "order_items":"cheesecake"}'
order = json.loads(json_data)
keys = order.keys()
print(list(keys))