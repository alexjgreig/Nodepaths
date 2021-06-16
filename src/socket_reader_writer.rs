use bindings::Windows::Networking::Sockets::StreamSocket;
use bindings::Windows::Storage::Streams::ByteOrder;
use bindings::Windows::Storage::Streams::DataReader;
use bindings::Windows::Storage::Streams::DataWriter;
use bindings::Windows::Storage::Streams::UnicodeEncoding;

use std::ptr;
use windows::HSTRING;

#[derive(Clone)]
pub struct SocketReaderWriter {
    pub data_reader: DataReader,
    pub data_writer: DataWriter,
    pub stream_socket: StreamSocket,
}

impl SocketReaderWriter {
    pub fn new(socket: StreamSocket) -> Self {
        let data_reader = DataReader::CreateDataReader(socket.InputStream().unwrap()).unwrap();
        data_reader.SetUnicodeEncoding(UnicodeEncoding::Utf8);
        data_reader.SetByteOrder(ByteOrder::LittleEndian);

        let data_writer = DataWriter::CreateDataWriter(socket.OutputStream().unwrap()).unwrap();
        data_writer.SetUnicodeEncoding(UnicodeEncoding::Utf8);
        data_writer.SetByteOrder(ByteOrder::LittleEndian);

        SocketReaderWriter {
            data_reader: data_reader,
            data_writer: data_writer,
            stream_socket: socket,
        }
    }
    pub fn close(&self) {
        &self.data_reader.Close();
        &self.data_writer.Close();
        &self.stream_socket.Close();
    }

    async fn write_message_async(&self, message: HSTRING) {
        &self
            .data_writer
            .WriteUInt32(self.data_writer.MeasureString(message.clone()).unwrap());
        &self.data_writer.WriteString(message.clone());
        &self.data_writer.StoreAsync().unwrap().await;
        println!("Sent Message {:?}", message.clone());
        //error handling
    }
    pub async fn read_message_async(&self) -> HSTRING {
        let mut bytes_read: u32 = self
            .data_reader
            .LoadAsync(u32::MAX)
            .unwrap()
            .GetResults()
            .unwrap();
        if bytes_read > 0 {
            let message_length: u32 = self.data_reader.ReadUInt32().unwrap();
            bytes_read = self
                .data_reader
                .LoadAsync(message_length)
                .unwrap()
                .await
                .unwrap();
            if bytes_read > 0 {
                let message: HSTRING = self.data_reader.ReadString(message_length).unwrap();
                println!("Receieved Message: {:?}", message);
                return message;
            }
        }
        return HSTRING::new();
    }
}
