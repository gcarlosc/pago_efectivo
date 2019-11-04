require 'savon'
require 'gyoku'
require 'nokogiri'
require 'rest-client'

module PagoEfectivo
  CURRENCIES = {soles: {id: 1, symbol: 'S/.'}, dolares: {id: 2, symbol: '$'}}
  # 1 => bancos
  # 2 => cuenta_virtual
  PAY_METHODS = [1,2]

  class Client
    SCHEMA_TYPES = {
      'xmlns:xsd' => 'http://www.w3.org/2001/XMLSchema',
      'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
      'xmlns:soap' => 'http://schemas.xmlsoap.org/soap/envelope/'
    }

    def initialize(options = {})
      raise 'Ingrese api_server y/o code_service. Obligatorio' unless options[:api_server] || options[:code_service]
      raise 'Ingrese access_key y/o secret_key. Obligatorio' unless options[:access_key] || options[:secret_key]
      @api_server = options[:api_server]
      @code_service = options[:code_service]
      @access_key = options[:access_key]
      @secret_key = options[:secret_key]
      crypto_path = '/PagoEfectivoWSCrypto/WSCrypto.asmx?WSDL'
      cip_path = '/PagoEfectivoWSGeneralv2/service.asmx?WSDL'
      crypto_service = @api_server + crypto_path
      cip_service = @api_server + cip_path
      savon_opts = {}
      savon_opts[:proxy] = ENV['PROXY_URL'] if options[:proxy]
      savon_opts[:ssl_verify_mode] = none if options[:ssl] == false

      @crypto_client = Savon.client({ wsdl: crypto_service }.merge(savon_opts))
      @cip_client = Savon.client({ wsdl: cip_service }.merge(savon_opts))
    end

    def generate_authorization date:
      parameter = [@code_service.to_s, @access_key, @secret_key, date.to_s].join('.')
      puts parameter
      param_hash = Digest::SHA256.hexdigest parameter
      params = {
                 "accessKey": @access_key,
                 "idService": @code_service,
                 "dateRequest": date.to_s,
                 "hashString": param_hash
               }

      response = RestClient.post "#{@api_server}/v1/authorizations", params
      res_json = JSON.parse(response.body)
      puts res_json
    end

    # def set_key type, path
    #   raise 'path to your key is not valid' unless File.exists?(path)
    #   if type == 'private'
    #     @private_key = File.open(path, 'rb') {|f| Base64.encode64(f.read)}
    #   elsif type == 'public'
    #     @public_key = File.open(path, 'rb') {|f| Base64.encode64(f.read)}
    #   end
    # end

   def create_markup(body)
     xml_markup = Nokogiri.XML(body).to_xml
   end

    def signature(text)
      response = @crypto_client.call(:signer, message: {
                                  plain_text: text, private_key: @private_key
                                })
      response.to_hash[:signer_response][:signer_result]
    end

    def encrypt_text(text)
      response = @crypto_client.call(:encrypt_text, message: {
                                  plain_text: text, public_key: @public_key
                                })
      response.to_hash[:encrypt_text_response][:encrypt_text_result]
    end

    def unencrypt enc_text
      response = @crypto_client.call(:decrypt_text, message: {
                                  encrypt_text: enc_text, private_key: @private_key
                                })
      response.to_hash[:decrypt_text_response][:decrypt_text_result]
    end

    # after unencrypt cip result this return like string so we need parse this
    # for access cip data in more easy way
    def parse_cip_result uncrypt_text, keys=[]
      parser = Nori.new
      cip = parser.parse uncrypt_text
      if keys.length > 0
        result = cip

        keys.map do |k|
          result = result[k]
        end
        result
      else
        cip
      end
    end

    def generate_xml(currency, total, pay_methods, cod_trans, email,
                     user, additional_data, exp_date, place, pay_concept,
                     origin_code, origin_type)
      # cod_serv => código de servicio asignado
      # signer => trama firmada con llave privada
      child_hash = { sol_pago: {
                 id_moneda: currency[:id],
                 total: total, # 18 enteros, 2 decimales. Separados por `,`
                 metodos_pago: pay_methods,
                 cod_servicio: @code_service,
                 codtransaccion: cod_trans, # referencia al pago
                 email_comercio: email,
                 fecha_a_expirar: exp_date, # (DateTime.now + 4).to_s(:db)
                 usuario_id: user[:id],
                 data_adicional: additional_data,
                 usuario_nombre: user[:first_name],
                 usuario_apellidos: user[:last_name],
                 usuario_localidad: place[:loc],
                 usuario_provincia: place[:prov],
                 usuario_pais: place[:country],
                 usuario_alias: '',
                 usuario_tipo_doc: user[:doc_type], # tipo de documento DNI, LE, RUC
                 usuario_numero_doc: user[:doc_num],
                 usuario_email: user[:email],
                 concepto_pago: pay_concept,
                 detalles: {
                   detalle: {
                     cod_origen: origin_code,
                     tipo_origen: origin_type,
                     concepto_pago: pay_concept,
                     importe: total,
                     campo1: '',
                     campo2: '',
                     campo3: '',
                   }
                 },
                 params_url: {
                   param_url: {
                     nombre: 'IDCliente',
                     valor: user[:id]
                   },
                   params_email: {
                     param_email: {
                       nombre: '[UsuarioNombre]',
                       valor: user[:first_name]
                     },
                     param_email: {
                       nombre: '[Moneda]',
                       valor: currency[:symbol]
                     }
                   }
                 }
               }
             }
      child_options = { key_converter: :camelcase}
      gyoku_xml = Gyoku.xml(child_hash, child_options)
      xml_child = create_markup(gyoku_xml)
    end

    def generate_cip(signer, xml)
      response = @cip_client.call(:generar_cip_mod1, message: {
                              request: {
                                'CodServ' => @code_service,
                                'Firma' => signer,
                                'Xml' => xml
                            }})
      response.to_hash[:generar_cip_mod1_response][:generar_cip_mod1_result]
    end

    # cod_serv: service code, provided by pago efectivo
    # cips: string of cips separated with comma (,)
    # signed_cips: cips passed by signer method
    # encrypted_cips: cips passed by encrypted method
    # info_request: no specified in pago efectivo documentation, send blank
    #               for now
    def consult_cip signed_cips, encrypted_cips, info_request=''
      response = @cip_client.call(:consultar_cip_mod1, message: {
                   'request' => {
                     'CodServ' => @code_service,
                     'Firma' => signed_cips,
                     'CIPS' => encrypted_cips,
                     info_request: info_request
                   }
                 })
      response.to_hash[:consultar_cip_mod1_response][:consultar_cip_mod1_result]
    end

    # after unencrypt consult cip result this return string so we need parse
    # this for access cip data in more easy way
    def parse_consult_cip_result uncrypt_text
      parser = Nori.new
      cip = parser.parse uncrypt_text
      # TODO: parse response for multiple cips
      cip['ConfirSolPagos']['ConfirSolPago']['CIP']
    end

    # cod_serv: service code, provided by pago efectivo
    # signed_cip: number of cip to delete passed by signer method
    # encrypted_cip: number of cip to delete passed by encrypted method
    # info_request: no specified in pago efectivo documentation, send blank
    #               for now
    def delete_cip signed_cip, encrypted_cip, info_request=''
      response = @cip_client.call(:eliminar_cip_mod1, message: {
                   'request' => {
                     'CodServ' => @code_service,
                     'Firma' => signed_cip,
                     'CIP' => encrypted_cip,
                     'InfoRequest' => info_request
                   }
                 })
      response.to_hash[:eliminar_cip_mod1_response][:eliminar_cip_mod1_result]
    end

    # cod_serv: service code, provided by pago efectivo
    # signed_cip: number of cip to modify passed by signer method
    # encrypted_cip: number of cip to modify passed by encrypted method
    # exp_date: new expiration date, should be DateTime class
    # info_request: no specified in pago efectivo documentation, send blank
    #               for now
    def update_cip signed_cip,encrypted_cip,exp_date,info_request=''
      response = @cip_client.call(:actualizar_cip_mod1, message: {
                   'request' => {
                     'CodServ' => @code_service,
                     'Firma' => signed_cip,
                     'CIP' => encrypted_cip,
                     'FechaExpira' => exp_date,
                     'InfoRequest' => info_request
                   }
                 })
      response.to_hash[:actualizar_cip_mod1_response][:actualizar_cip_mod1_result]
    end
  end
end
