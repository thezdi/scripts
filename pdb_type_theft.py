#!/usr/bin/env python

from struct import unpack
from struct import pack
from struct import calcsize

DEBUG = False

# The following classes are all based on pdbparse at https://github.com/moyix/pdbparse
# They are partially reimplemented/extended as we care far less about the data within each stream
# I initially monkey patched things in but ultimately decided that reimplementing was easier
# The code and wiki at https://code.google.com/p/pdbparser/ was also invaluable

class PDBException(Exception): pass 
class PDBParseException(PDBException): pass 
class PDBDumpException(PDBException): pass 
class PDBSignatureException(PDBParseException): pass 

ROOT_STREAM = 0
TPI_STREAM = 2

class PDB7(object):
    _PDB7_SIGNATURE = 'Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0'
    _PDB7_SIGNATURE_LEN = len(_PDB7_SIGNATURE)
    _PDB7_FMT = "<%dsIIIII" % _PDB7_SIGNATURE_LEN
    _PDB7_FMT_SIZE = calcsize(_PDB7_FMT)

    def __init__(self, file_h):
        self.signature = None
        self.page_size = None
        self.free_page_map = None
        self.num_file_pages = None
        self.root_size = None
        self.reserved = None

        self.untouched_page_map = None

        self.streams = None

        self.load(file_h)

    def _num_pages(self, size):
        return size / self.page_size + (size % self.page_size != 0)

    def _data_from_page(self, file_h, page):
        file_h.seek(page * self.page_size)

        return file_h.read(self.page_size)

    def _data_from_pages(self, file_h, pages, size):
        return ''.join(self._data_from_page(file_h, page) for page in pages)[:size]

    def _data_to_page(self, file_h, page, data):
        file_h.seek(page * self.page_size)

        file_h.write(data)

    def _data_to_pages(self, file_h, pages, data):
        if len(pages) == 0 and len(data) != 0:
            raise PDBDumpException('Expected to have pages to write data to')

        i = 0
        for i, page in enumerate(pages):
            self._data_to_page(file_h, page, data[i*self.page_size:(i+1)*self.page_size])

        if (i+1) * self.page_size < len(data):
            raise PDBDumpException('Not enough pages to write data to')

    def _get_next_page(self, page):
        page += 1

        while page in self.untouched_page_map:
            page += 1

        return page

    def load(self, file_h):
        file_h.seek(0)

        (self.signature, self.page_size, self.free_page_map,
         self.num_file_pages, self.root_size, self.reserved) = unpack(self._PDB7_FMT, file_h.read(self._PDB7_FMT_SIZE))
        
        if self.signature != self._PDB7_SIGNATURE:
            raise PDBSignatureException("Invalid signature for PDB version 7")
        
        num_root_pages = self._num_pages(self.root_size)

        # Skip the header
        untouched_page_set = set(xrange(1, self.num_file_pages))

        num_root_index_pages = self._num_pages(num_root_pages*4)
        root_index_array_fmt = '<%dI' % num_root_index_pages
        root_index_pages = unpack(root_index_array_fmt, file_h.read(num_root_index_pages*4))
        untouched_page_set.difference_update(root_index_pages)
        
        root_page_data = self._data_from_pages(file_h, root_index_pages, num_root_pages*4)
        
        page_list_fmt = '<%dI' % num_root_pages
        root_page_list = unpack(page_list_fmt, root_page_data)
        untouched_page_set.difference_update(root_page_list)

        self.root_stream = PDB7RootStream(self, self._data_from_pages(file_h, root_page_list, self.root_size))

        if len(self.root_stream.stream_pages) == 0:
            raise PDBParseException('There are no streams within this PDB')

        self.streams = []
        stream_id_class_map = {ROOT_STREAM:PDB7RootStream, TPI_STREAM:PDBTPIStream}

        for i in xrange(len(self.root_stream.stream_sizes)):
            klass = stream_id_class_map.get(i, PDBGenericStream)
            data = self._data_from_pages(file_h, self.root_stream.stream_pages[i], self.root_stream.stream_sizes[i])
            untouched_page_set.difference_update(self.root_stream.stream_pages[i])
            self.streams.append(klass(self, data))

            if DEBUG:
                print 'Stream %04d of size %08d starts with %r' % (i, self.root_stream.stream_sizes[i], unpack('%dI' % (min(8, len(data))/4), data[:min(8, len(data))]))

        for i in xrange(len(self.streams[ROOT_STREAM].stream_sizes)):
            untouched_page_set.difference_update(self.streams[ROOT_STREAM].stream_pages[i])

        # Keeping this for now out of ignorance, since we do not parse all the streams
        self.untouched_page_map = {}
        for untouched_page in untouched_page_set:
            data = self._data_from_page(file_h, untouched_page)
            # Though if the page only contains NULL, we won't bother saving it
            if len(set(data)) == 1 and data[0] == '\x00':
                continue

            self.untouched_page_map[untouched_page] = data

    def dump(self, outfile_h=None):
        outfile_h.seek(0)

        for untouched_page, untouched_data in self.untouched_page_map.iteritems():
            self._data_to_page(outfile_h, untouched_page, untouched_data)

        stream_sizes = []
        stream_pages = []
        last_page = 1
        for stream in self.streams:
            data = stream._get_data()
            stream_size = len(data)

            if DEBUG:
                print 'Stream %04d of size %08d starts with %r' % (len(stream_sizes), stream_size, unpack('%dI' % (min(8, stream_size)/4), data[:min(8, stream_size)]))

            stream_sizes.append(stream_size)
            pages = []
            for i in xrange(self._num_pages(stream_size)):
                pages.append(last_page)
                last_page = self._get_next_page(last_page)

            self._data_to_pages(outfile_h, pages, data)
            stream_pages.append(tuple(pages))

        self.root_stream.stream_sizes = stream_sizes
        self.root_stream.stream_pages = stream_pages
        root_page_data = self.root_stream._get_data()

        num_root_pages = self._num_pages(len(root_page_data))

        root_pages = []
        for i in xrange(num_root_pages):
            root_pages.append(last_page)
            last_page = self._get_next_page(last_page)

        self._data_to_pages(outfile_h, root_pages, root_page_data)

        self.streams[ROOT_STREAM].stream_sizes = stream_sizes
        self.streams[ROOT_STREAM].stream_pages = stream_pages
        self.streams[ROOT_STREAM].stream_sizes[ROOT_STREAM] = len(root_page_data)
        self.streams[ROOT_STREAM].stream_pages[ROOT_STREAM] = root_pages

        num_root_index_pages = self._num_pages(num_root_pages*4)
        if num_root_index_pages > 0x49:
            raise PDBDumpException('Invalid root stream, can not exceed 0x49 index pages')

        root_index_pages = []
        for i in xrange(num_root_index_pages):
            root_index_pages.append(last_page)
            last_page = self._get_next_page(last_page)

        self._data_to_pages(outfile_h, root_index_pages, pack('%dI' % len(root_pages), *root_pages))
        
        self.num_file_pages = last_page
        self.root_size = len(root_page_data)

        outfile_h.seek(0)
        outfile_h.write(pack(self._PDB7_FMT, self.signature, self.page_size, self.free_page_map,
                             self.num_file_pages, self.root_size, self.reserved))

        outfile_h.write(pack('%dI' % num_root_index_pages, *root_index_pages))
        outfile_h.write('\x00' * (outfile_h.tell() - self.page_size))

        outfile_h.close()

class PDBStream(object):
    def __init__(self, parent):
        self.parent = parent

    def _get_data(self):
        raise NotImplementedError('_get_data called on base class')

    def _update_data(self):
        pass

class PDBGenericStream(PDBStream):
    def __init__(self, parent, data):
        super(PDBGenericStream, self).__init__(parent)
        self.data = data

    def _get_data(self):
        return self.data

class PDBTPIStream(PDBGenericStream):
    # This is not complete, but is enough for what we need
    _TPI_FMT = 'IiIIIHHiiiiiiii'
    _TPI_FMT_SIZE = calcsize(_TPI_FMT)

    def __init__(self, parent, data):
        super(PDBTPIStream, self).__init__(parent, data)

        # Parsing the TPI stream header as well as the TPIHash struct
        (self.version, self.header_size, self.ti_base, self.ti_max, self.rec_size,
         self.stream, self.padding, self.hash_key_size, self.hash_buckets_size,
         self.hash_values_offset, self.hash_values_size, self.type_info_offset,
         self.type_info_size, self.hash_adj_offset, self.hash_adj_size,) = unpack(self._TPI_FMT, data[:self._TPI_FMT_SIZE])

        if not 0 <= self.stream < len(parent.root_stream.stream_sizes):
            print self.stream
            raise PDBParseException('TPI stream specifies an invalid stream within the TPIHash struct')

    def _update_data(self):
        updated_header = pack(self._TPI_FMT, self.version, self.header_size,
                              self.ti_base, self.ti_max, self.rec_size,
                              self.stream, self.padding, self.hash_key_size,
                              self.hash_buckets_size, self.hash_values_offset,
                              self.hash_values_size, self.type_info_offset,
                              self.type_info_size, self.hash_adj_offset,
                              self.hash_adj_size,)

        self.data = updated_header + self.data[self._TPI_FMT_SIZE:]

class PDB7RootStream(PDBStream):
    def __init__(self, parent, data_str):
        super(PDB7RootStream, self).__init__(parent)

        if len(data_str) % 4:
            raise PDBParseException('Invalid root stream, data length is not DWORD aligned')

        if len(data_str) == 0:
            raise PDBParseException('Invalid root stream, there is no data')

        data = unpack('%dI' % (len(data_str)/4), data_str)

        num_streams = data[0]

        if num_streams == 0:
            raise PDBParseException('Invalid root stream, it specifies no streams')

        if len(data) < 1 + num_streams:
            raise PDBParseException('Invalid root stream, specified number of streams is larger than what is available')

        pos = num_streams + 1
        self.stream_sizes = []
        self.stream_pages = []

        for i in xrange(num_streams):
            stream_size = data[i+1]
            if stream_size == 0xffffffff:
                stream_size = 0

            self.stream_sizes.append(stream_size)
            num_stream_pages = self.parent._num_pages(stream_size)
            if pos + num_stream_pages > len(data):
                raise PDBParseException('Invalid root stream, stream size exceeds available data')

            self.stream_pages.append(tuple(data[pos:pos+num_stream_pages]))
            pos += num_stream_pages

        if pos < len(data):
            raise PDBParseException('Invalid root stream, did not consume all data')

    def _get_data(self):
        data = [len(self.stream_sizes)]
        data.extend(self.stream_sizes)
        for pages in self.stream_pages:
            data.extend(pages)

        return pack('%dI' % len(data), *data)

def type_theft(pdb_with_types, pdb_to_update):
    with open(pdb_with_types, 'rb') as file_h:
        base_pdb = PDB7(file_h)

    with open(pdb_to_update, 'rb') as file_h:
        new_pdb = PDB7(file_h)

    base_tpi_hash_stream = base_pdb.streams[TPI_STREAM].stream
    new_tpi_hash_stream = new_pdb.streams[TPI_STREAM].stream

    if DEBUG:
        print 'Base TPI hash stream: %08d' % base_tpi_hash_stream
        print 'New TPI hash stream: %08d' % new_tpi_hash_stream

        print 'Base TPI stream size: %08x' % len(base_pdb.streams[TPI_STREAM]._get_data())
        print 'Old TPI stream size: %08x' % len(new_pdb.streams[TPI_STREAM]._get_data())
        print 'Base TPI hash stream size: %08x' % len(base_pdb.streams[base_tpi_hash_stream]._get_data())
        print 'Old TPI hash stream size: %08x' % len(new_pdb.streams[new_tpi_hash_stream]._get_data())

    new_pdb.streams[TPI_STREAM] = base_pdb.streams[TPI_STREAM]
    if DEBUG:
        print 'TPI hash stream was: %08d' % new_pdb.streams[TPI_STREAM].stream
    new_pdb.streams[TPI_STREAM].stream = new_tpi_hash_stream
    new_pdb.streams[TPI_STREAM]._update_data()
    if DEBUG:
        print '\t...but is now : %08d' % new_pdb.streams[TPI_STREAM].stream
    new_pdb.streams[new_tpi_hash_stream] = base_pdb.streams[base_tpi_hash_stream]

    output_pdb = pdb_to_update + '.patched'
    with open(output_pdb, 'wb') as file_h:
        new_pdb.dump(file_h)

    print 'PDB successfully written to %s' % output_pdb

def main():
    import sys

    if len(sys.argv) != 3:
        print 'Usage:'
        print '\t%s PDB_WITH_TYPES PDB_TO_UPDATE' % sys.argv[0]
        print 'Type info will be read from PDB_WITH_TYPES and written to PDB_TO_UPDATE.patched'
        sys.exit(-1)

    type_theft(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()

