

class AbstractParser(object):
    """ A Parser takes a data source and converts it into a Chunk """
    pass


class StreamParser(AbstractParser):
    pass


class TemplateStreamParser(AbstractParser):
    """ The template parser parses some raw data according to a template """
    def __init__(self, template):
        self.template = template

    def parse_stream(self, raw_stream_data):
        chunk_internal_value = []
        raw_stream_remain = raw_stream_data

        for chunk_type, chunk_args in self.template:
            # chunk_args['parent'] = self
            # chunk_args['raw_data'] = raw_stream_remain[:]
            try:
                new_chunk = chunk_type(**chunk_args)
                chunk_internal_value.append(new_chunk)
                new_chunk.internal_value, raw_stream_remain = new_chunk.read_from_stream(raw_stream_remain)
            except Exception as e:
                print("TemplateStreamParser: Failed to initialise a component of template")
                print("chunk_type: %s chunk_args: %s" % (chunk_type, chunk_args))
                raise

        return chunk_internal_value