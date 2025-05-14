from flask import Flask, render_template, request, redirect, url_for, g, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime

app = Flask(__name__)
DATABASE = 'estoque.db'
app.secret_key = 'sua_chave_secreta'  # ***SUBSTITUA POR UMA CHAVE SECRETA FORTE!***
database_initialized = False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, args)
    rv = cursor.fetchall()
    cursor.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    conn = get_db()
    with conn:
        cursor = conn.cursor()
        cursor.execute(query, args)
        return cursor.lastrowid    

def adicionar_coluna_estoque_atual():
    conn = sqlite3.connect('estoque.db')
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE produtos ADD COLUMN estoque_atual INTEGER NOT NULL DEFAULT 0;")
        conn.commit()
        print("Coluna 'estoque_atual' adicionada com sucesso.")
    except sqlite3.OperationalError as e:
        print(f"Erro ao adicionar coluna: {e}")
        print("A coluna 'estoque_atual' pode já existir.")
    finally:
        conn.close()

adicionar_coluna_estoque_atual()


def criar_tabelas():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS depositos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            descricao TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS armarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deposito_id INTEGER NOT NULL,
            nome TEXT NOT NULL,
            descricao TEXT,
            FOREIGN KEY (deposito_id) REFERENCES depositos(id),
            UNIQUE (deposito_id, nome)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prateleiras_gavetas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            armario_id INTEGER NOT NULL,
            tipo TEXT NOT NULL, -- 'gaveta' ou 'prateleira'
            numero TEXT NOT NULL,
            descricao TEXT,
            FOREIGN KEY (armario_id) REFERENCES armarios(id),
            UNIQUE (armario_id, tipo, numero)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS localizacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produto_id INTEGER NOT NULL,
            deposito_id INTEGER NOT NULL,
            armario_id INTEGER NOT NULL,
            prateleira_gaveta_id INTEGER NOT NULL,
            quantidade INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (produto_id) REFERENCES produtos(id),
            FOREIGN KEY (deposito_id) REFERENCES depositos(id),
            FOREIGN KEY (armario_id) REFERENCES armarios(id),
            FOREIGN KEY (prateleira_gaveta_id) REFERENCES prateleiras_gavetas(id),
            UNIQUE (produto_id, prateleira_gaveta_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT UNIQUE NOT NULL,
            nome TEXT UNIQUE NOT NULL,
            descricao TEXT,
            unidade_medida TEXT NOT NULL,
            estoque_minimo INTEGER NOT NULL DEFAULT 0,
            preco_custo REAL,
            preco_venda REAL,
            data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produto_id INTEGER NOT NULL,
            data_entrada DATE NOT NULL,
            quantidade INTEGER NOT NULL,
            fornecedor TEXT,
            data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usuario_id INTEGER,
            FOREIGN KEY (produto_id) REFERENCES produtos(id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saidas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produto_id INTEGER NOT NULL,
            data_saida DATE NOT NULL,
            quantidade INTEGER NOT NULL,
            motivo TEXT,
            cliente TEXT,
            data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usuario_id INTEGER,
            FOREIGN KEY (produto_id) REFERENCES produtos(id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            tipo TEXT NOT NULL DEFAULT 'operador',
            data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movimentacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produto_id INTEGER,
            data DATETIME,
            tipo TEXT,
            quantidade INTEGER,
            localizacao_tipo TEXT,
            localizacao_id INTEGER,
            usuario_id INTEGER,
            observacoes TEXT,
            FOREIGN KEY (produto_id) REFERENCES produtos(id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    ''')

    db.commit()
    cursor.close()

@app.before_request
def before_request():
    global database_initialized
    if not database_initialized:
        with app.app_context():
            criar_tabelas()
            database_initialized = True

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    erro = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username:
            erro = 'Nome de usuário é obrigatório.'
        elif not password:
            erro = 'Senha é obrigatória.'
        elif password != confirm_password:
            erro = 'As senhas não coincidem.'
        elif query_db('SELECT id FROM usuarios WHERE username = ?', [username], one=True):
            erro = 'Nome de usuário já existe.'
        else:
            hashed_password = generate_password_hash(password)
            execute_db('INSERT INTO usuarios (username, password) VALUES (?, ?)', [username, hashed_password])
            return redirect(url_for('login'))
    return render_template('registrar.html', erro=erro)

@app.route('/login', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = query_db('SELECT id, password, tipo FROM usuarios WHERE username = ?', [username], one=True)

        if user is None:
            erro = 'Nome de usuário incorreto.'
        elif not check_password_hash(user['password'], password):
            erro = 'Senha incorreta.'
        else:
            session['user_id'] = user['id']
            session['user_type'] = user['tipo']
            return redirect(url_for('index'))
    return render_template('login.html', erro=erro)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_type', None)
    return redirect(url_for('login'))

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session or session['user_type'] != 'administrador':
            return "Acesso não autorizado.", 403
        return view(*args, **kwargs)
    return wrapped_view

def operador_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session or session['user_type'] not in ['administrador', 'operador']:
            return "Acesso não autorizado.", 403
        return view(*args, **kwargs)
    return wrapped_view

@app.route('/produtos', methods=['GET'])
@operador_required
def listar_produtos():
    """Exibe a lista de produtos com detalhes de localização."""

    depositos = query_db('SELECT id, nome FROM depositos')
    armarios = query_db('SELECT id, nome, deposito_id FROM armarios')  # Busque todos os armários
    produtos = query_db("""
        SELECT
            p.id,
            p.codigo,
            p.nome,
            p.estoque_minimo,
            p.estoque_atual,
            d.nome as deposito_nome,
            d.id as deposito_id,  -- Pegue o ID do depósito
            a.nome as armario_nome,
            a.id as armario_id,    -- Pegue o ID do armário
            pg.tipo as prateleira_gaveta_tipo,
            pg.numero as prateleira_gaveta_numero
        FROM
            produtos p
        LEFT JOIN
            localizacoes l ON p.id = l.produto_id
        LEFT JOIN
            prateleiras_gavetas pg ON l.prateleira_gaveta_id = pg.id
        LEFT JOIN
            armarios a ON pg.armario_id = a.id
        LEFT JOIN
            depositos d ON a.deposito_id = d.id
        GROUP BY p.id
    """)

    produtos_dict = []
    for produto in produtos:
        produto_dict = dict(produto)
        if produto_dict['estoque_atual'] > produto_dict['estoque_minimo']:
            produto_dict['estoque_status'] = 'OK'
        else:
            produto_dict['estoque_status'] = 'Abaixo do Mínimo'
        produtos_dict.append(produto_dict)

    return render_template(
        'listar_produtos.html',
        produtos=produtos_dict,
        depositos=depositos,
        armarios=armarios,
        deposito_selecionado=0,  # Inicialize como 0
        armario_selecionado=0
    )

@app.route('/adicionar_produto', methods=['GET', 'POST'])
@admin_required
def adicionar_produto():
    erro_codigo = None
    erro_nome = None
    depositos = query_db('SELECT id, nome FROM depositos')
    armarios = query_db('SELECT id, nome, deposito_id FROM armarios')
    prateleiras_gavetas = query_db('SELECT id, tipo, numero, armario_id FROM prateleiras_gavetas')

    if request.method == 'POST':
        codigo = request.form['codigo']
        nome = request.form['nome'].upper()
        unidade_medida = request.form['unidade_medida']
        estoque_minimo = request.form['estoque_minimo']
        deposito_id = request.form['deposito_id']
        armario_id = request.form.get('armario_id')
        prateleira_gaveta_id = request.form.get('prateleira_gaveta_id')

        produto_com_codigo = query_db('SELECT id FROM produtos WHERE codigo = ?', [codigo], one=True)
        if produto_com_codigo:
            erro_codigo = 'Código já cadastrado em outro produto.'

        produto_com_nome = query_db('SELECT id FROM produtos WHERE nome = ?', [nome], one=True)
        if produto_com_nome:
            erro_nome = 'Produto já cadastrado.'

        if erro_codigo or erro_nome:
            pass
        elif not codigo:
            erro_codigo = 'O código do produto é obrigatório.'
        elif not nome:
            erro_nome = 'O nome do produto é obrigatório.'
        elif not unidade_medida:
            erro = 'A unidade de medida é obrigatória.'
        elif not estoque_minimo.isdigit():
            erro = 'O estoque mínimo deve ser um número inteiro.'
        elif not deposito_id:
            erro = 'O depósito é obrigatório.'
        else:
            execute_db('INSERT INTO produtos (codigo, nome, unidade_medida, estoque_minimo) VALUES (?, ?, ?, ?)',
                       (codigo, nome, unidade_medida, estoque_minimo))
            produto_id = query_db('SELECT id FROM produtos WHERE codigo = ?', [codigo], one=True)['id']
            data_atual = datetime.datetime.now()
            usuario_id = session.get('user_id')

            # Inserir na tabela localizacoes
            execute_db('''
                INSERT INTO localizacoes (produto_id, deposito_id, armario_id, prateleira_gaveta_id, quantidade)
                VALUES (?, ?, ?, ?, ?)
            ''', (produto_id, deposito_id, armario_id, prateleira_gaveta_id, 1))

            execute_db('INSERT INTO movimentacoes (produto_id, data, tipo, quantidade, localizacao_tipo, localizacao_id, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (produto_id, data_atual, 'entrada', 1, 'deposito', deposito_id, usuario_id)) # Ajustei a localizacao aqui

            return redirect(url_for('listar_produtos'))

    return render_template('adicionar_produto.html', erro_codigo=erro_codigo, erro_nome=erro_nome, depositos=depositos, armarios=armarios, prateleiras_gavetas=prateleiras_gavetas)

@app.route('/editar_produto/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_produto(id):
    produto = query_db('SELECT id, codigo, nome, unidade_medida, estoque_minimo FROM produtos WHERE id = ?', [id], one=True)
    if not produto:
        return "Produto não encontrado.", 404

    erro_codigo = None
    erro_nome = None

    if request.method == 'POST':
        codigo = request.form['codigo']
        nome = request.form['nome'].upper()
        unidade_medida = request.form['unidade_medida']
        estoque_minimo = request.form['estoque_minimo']

        produto_com_codigo = query_db('SELECT id FROM produtos WHERE codigo = ? AND id != ?', [codigo, id], one=True)
        if produto_com_codigo:
            erro_codigo = 'Código já cadastrado em outro produto.'

        produto_com_nome = query_db('SELECT id FROM produtos WHERE nome = ? AND id != ?', [nome, id], one=True)
        if produto_com_nome:
            erro_nome = 'Produto já cadastrado.'

        if erro_codigo or erro_nome:
            pass
        elif not codigo:
            erro_codigo = 'O código do produto é obrigatório.'
        elif not nome:
            erro_nome = 'O nome do produto é obrigatório.'
        elif not unidade_medida:
            erro = 'A unidade de medida é obrigatória.'
        elif not estoque_minimo.isdigit():
            erro = 'O estoque mínimo deve ser um número inteiro.'
        else:
            execute_db('UPDATE produtos SET codigo = ?, nome = ?, unidade_medida = ?, estoque_minimo = ? WHERE id = ?',
                       (codigo, nome, unidade_medida, estoque_minimo, id))
            return redirect(url_for('listar_produtos'))

    return render_template('editar_produto.html', produto=produto, erro_codigo=erro_codigo, erro_nome=erro_nome)

@app.route('/excluir_produto/<int:id>')
@admin_required
def excluir_produto(id):
    execute_db('DELETE FROM produtos WHERE id = ?', [id])
    return redirect(url_for('listar_produtos'))

@app.route('/registrar_entrada', methods=['GET', 'POST'])
@admin_required
def registrar_entrada():
    produtos = query_db('SELECT id, nome FROM produtos')
    erro = None
    if request.method == 'POST':
        produto_id = request.form['produto_id']
        data_entrada = request.form['data_entrada']
        quantidade = request.form['quantidade']

        if not produto_id:
            erro = 'Selecione um produto.'
        elif not data_entrada:
            erro = 'A data de entrada é obrigatória.'
        elif not quantidade.isdigit() or int(quantidade) <= 0:
            erro = 'A quantidade deve ser um número inteiro positivo.'
        else:
            execute_db('INSERT INTO entradas (produto_id, data_entrada, quantidade, usuario_id) VALUES (?, ?, ?, ?)',
                       (produto_id, data_entrada, quantidade, session['user_id']))
            # Atualiza o estoque do produto
            execute_db('UPDATE produtos SET estoque_atual = estoque_atual + ? WHERE id = ?', (quantidade, produto_id))
            flash('Entrada registrada com sucesso!', 'success')
            return redirect(url_for('registrar_entrada'))
    return render_template('registrar_entrada.html', produtos=produtos, erro=erro)

@app.route('/registrar_saida', methods=['GET', 'POST'])
@operador_required
def registrar_saida():
    produtos = query_db('SELECT id, nome FROM produtos')
    erro = None
    if request.method == 'POST':
        produto_id = request.form['produto_id']
        data_saida = request.form['data_saida']
        quantidade = request.form['quantidade']
        motivo = request.form.get('motivo')
        cliente = request.form.get('cliente')

        if not produto_id:
            erro = 'Selecione um produto.'
        elif not data_saida:
            erro = 'A data de saída é obrigatória.'
        elif not quantidade.isdigit() or int(quantidade) <= 0:
            erro = 'A quantidade deve ser um número inteiro positivo.'
        else:
            try:
                produto = query_db('SELECT estoque_atual FROM produtos WHERE id = ?', [produto_id], one=True)
                if not produto:
                    erro = 'Produto não encontrado.'
                    return render_template('registrar_saida.html', produtos=produtos, erro=erro)

                if produto['estoque_atual'] < int(quantidade):
                    erro = 'Estoque insuficiente.'
                    return render_template('registrar_saida.html', produtos=produtos, erro=erro)

                # 1. Registrar a saída
                execute_db('INSERT INTO saidas (produto_id, data_saida, quantidade, motivo, cliente, usuario_id) VALUES (?, ?, ?, ?, ?, ?)',
                           (produto_id, data_saida, quantidade, motivo, cliente, session['user_id']))

                # 2. Atualizar o estoque geral
                execute_db('UPDATE produtos SET estoque_atual = estoque_atual - ? WHERE id = ?', (quantidade, produto_id))

                # 3. Atualizar as localizações (lógica mais complexa)
                quantidade_a_retirar = int(quantidade)
                localizacoes = query_db('SELECT id, quantidade FROM localizacoes WHERE produto_id = ? ORDER BY quantidade DESC', [produto_id])

                for localizacao in localizacoes:
                    if quantidade_a_retirar > 0:
                        quantidade_neste_local = localizacao['quantidade']
                        localizacao_id = localizacao['id']

                        print(f"  - Localização {localizacao_id}: {quantidade_neste_local} itens, a retirar: {quantidade_a_retirar}")

                        if quantidade_neste_local >= quantidade_a_retirar:
                            # Retirar tudo deste local
                            nova_quantidade = quantidade_neste_local - quantidade_a_retirar
                            execute_db('UPDATE localizacoes SET quantidade = ? WHERE id = ?', (nova_quantidade, localizacao_id))
                            print(f"    -> Retirado {quantidade_a_retirar} de localizacao {localizacao_id}. Nova quantidade: {nova_quantidade}")
                            quantidade_a_retirar = 0
                            break
                        else:
                            # Retirar o máximo possível deste local
                            execute_db('UPDATE localizacoes SET quantidade = 0 WHERE id = ?', (localizacao_id,))
                            print(f"    -> Retirado {quantidade_neste_local} de localizacao {localizacao_id}. Quantidade zerada.")
                            quantidade_a_retirar -= quantidade_neste_local
                            print(f"       Quantidade restante a retirar: {quantidade_a_retirar}")

                # Verificação CRUCIAL após o loop
                total_retirado_localizacoes = int(quantidade) - quantidade_a_retirar
                print(f"Total retirado das localizações: {total_retirado_localizacoes}, Quantidade original: {quantidade}")
                
                flash('Saída registrada com sucesso!', 'success')
                return redirect(url_for('registrar_saida'))

            except sqlite3.Error as e:
                erro = f'Erro ao registrar saída: {str(e)}'
                print(f"Erro de banco de dados: {str(e)}")
                return render_template('registrar_saida.html', produtos=produtos, erro=erro)

    return render_template('registrar_saida.html', produtos=produtos, erro=erro)

@app.route('/usuarios')
@admin_required
def listar_usuarios():
    usuarios = query_db('SELECT id, username, tipo, data_registro FROM usuarios')
    return render_template('listar_usuarios.html', usuarios=usuarios)

@app.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(id):
    usuario = query_db('SELECT id, username, tipo FROM usuarios WHERE id = ?', [id], one=True)
    if not usuario:
        return "Usuário não encontrado.", 404
    erro = None
    if request.method == 'POST':
        tipo = request.form['tipo']
        execute_db('UPDATE usuarios SET tipo = ? WHERE id = ?', [tipo, id])
        return redirect(url_for('listar_usuarios'))
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/usuarios/excluir/<int:id>')
@admin_required
def excluir_usuario(id):  # Nome correto da função
    execute_db('DELETE FROM usuarios WHERE id = ?', [id])
    return redirect(url_for('listar_usuarios'))

@app.route('/usuarios/adicionar', methods=['GET', 'POST'])
@admin_required
def adicionar_usuario():
    erro = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        tipo = request.form['tipo']
        if not username:
            erro = 'Nome de usuário é obrigatório.'
        elif not password:
            erro = 'Senha é obrigatória.'
        elif query_db('SELECT id FROM usuarios WHERE username = ?', [username], one=True):
            erro = 'Nome de usuário já existe.'
        else:
            hashed_password = generate_password_hash(password)
            execute_db('INSERT INTO usuarios (username, password, tipo) VALUES (?, ?, ?)', [username, hashed_password, tipo])
            return redirect(url_for('listar_usuarios'))
    return render_template('adicionar_usuario.html', erro=erro)

@app.route('/depositos')
@admin_required
def listar_depositos():
    depositos = query_db('SELECT id, nome, descricao FROM depositos')
    return render_template('listar_depositos.html', depositos=depositos, datetime=datetime)

@app.route('/depositos/adicionar', methods=['GET', 'POST'])
@admin_required
def adicionar_deposito():
    erro = None
    if request.method == 'POST':
        nome = request.form['nome'].upper()
        descricao = request.form['descricao']
        if not nome:
            erro = 'O nome do depósito é obrigatório.'
        elif query_db('SELECT id FROM depositos WHERE nome = ?', [nome], one=True):
            erro = 'Já existe um depósito com este nome.'
        else:
            execute_db('INSERT INTO depositos (nome, descricao) VALUES (?, ?)', [nome, descricao])
            return redirect(url_for('listar_depositos'))
    return render_template('adicionar_deposito.html', erro=erro, datetime=datetime)     

@app.route('/depositos/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_deposito(id):
    deposito = query_db('SELECT id, nome, descricao FROM depositos WHERE id = ?', [id], one=True)
    if not deposito:
        return "Depósito não encontrado.", 404
    erro = None
    if request.method == 'POST':
        nome = request.form['nome'].upper()
        descricao = request.form['descricao']
        if not nome:
            erro = 'O nome do depósito é obrigatório.'
        elif query_db('SELECT id FROM depositos WHERE nome = ? AND id != ?', [nome, id], one=True):
            erro = 'Já existe um depósito com este nome.'
        else:
            execute_db('UPDATE depositos SET nome = ?, descricao = ? WHERE id = ?', [nome, descricao, id])
            return redirect(url_for('listar_depositos'))
    return render_template('editar_deposito.html', deposito=deposito, erro=erro, datetime=datetime)

@app.route('/depositos/excluir/<int:id>')
@admin_required
def excluir_deposito(id):
    # Adicionar verificação se existem armários vinculados antes de excluir
    armarios_vinculados = query_db('SELECT id FROM armarios WHERE deposito_id = ?', [id])
    if armarios_vinculados:
        return "Não é possível excluir o depósito pois existem armários vinculados a ele.", 400
    execute_db('DELETE FROM depositos WHERE id = ?', [id])
    return redirect(url_for('listar_depositos'))

# Rota temporária para criar o primeiro administrador (REMOVER APÓS O USO!)
@app.route('/criar_admin_inicial')
def criar_admin_inicial():
    username = 'admin'  # Defina o nome de usuário desejado
    password = 'sua_senha_admin'  # ***SUBSTITUA POR UMA SENHA FORTE!***

    hashed_password = generate_password_hash(password)

    try:
        execute_db('INSERT INTO usuarios (username, password, tipo) VALUES (?, ?, ?)', [username, hashed_password, 'administrador'])
        return "Administrador inicial criado com sucesso! (Lembre-se de remover esta rota)"
    except sqlite3.IntegrityError:
        return "Usuário 'admin' já existe."

@app.route('/depositos/<int:deposito_id>/armarios')
@admin_required
def listar_armarios(deposito_id):
    deposito = query_db('SELECT id, nome FROM depositos WHERE id = ?', [deposito_id], one=True)
    if not deposito:
        return "Depósito não encontrado.", 404
    armarios = query_db('SELECT id, nome, descricao FROM armarios WHERE deposito_id = ?', [deposito_id])
    return render_template('listar_armarios.html', deposito=deposito, armarios=armarios, datetime=datetime)    

@app.route('/depositos/<int:deposito_id>/armarios/adicionar', methods=['GET', 'POST'])
@admin_required
def adicionar_armario(deposito_id):
    deposito = query_db('SELECT id, nome FROM depositos WHERE id = ?', [deposito_id], one=True)
    if not deposito:
        return "Depósito não encontrado.", 404
    erro = None
    if request.method == 'POST':
        nome = request.form['nome'].upper()
        descricao = request.form['descricao']
        if not nome:
            erro = 'O nome do armário é obrigatório.'
        elif query_db('SELECT id FROM armarios WHERE deposito_id = ? AND nome = ?', [deposito_id, nome], one=True):
            erro = 'Já existe um armário com este nome neste depósito.'
        else:
            execute_db('INSERT INTO armarios (deposito_id, nome, descricao) VALUES (?, ?, ?)', [deposito_id, nome, descricao])
            return redirect(url_for('listar_armarios', deposito_id=deposito_id))
    return render_template('adicionar_armario.html', deposito=deposito, erro=erro, datetime=datetime)

@app.route('/armarios/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_armario(id):
    armario = query_db('SELECT id, deposito_id, nome, descricao FROM armarios WHERE id = ?', [id], one=True)
    if not armario:
        return "Armário não encontrado.", 404
    deposito = query_db('SELECT id, nome FROM depositos WHERE id = ?', [armario['deposito_id']], one=True)
    erro = None
    if request.method == 'POST':
        nome = request.form['nome'].upper()
        descricao = request.form['descricao']
        if not nome:
            erro = 'O nome do armário é obrigatório.'
        elif query_db('SELECT id FROM armarios WHERE deposito_id = ? AND nome = ? AND id != ?', [armario['deposito_id'], nome, id], one=True):
            erro = 'Já existe um armário com este nome neste depósito.'
        else:
            execute_db('UPDATE armarios SET nome = ?, descricao = ? WHERE id = ?', [nome, descricao, id])
            return redirect(url_for('listar_armarios', deposito_id=armario['deposito_id']))
    return render_template('editar_armario.html', armario=armario, deposito=deposito, erro=erro, datetime=datetime)    

@app.route('/armarios/excluir/<int:id>')
@admin_required
def excluir_armario(id):
    armario = query_db('SELECT deposito_id FROM armarios WHERE id = ?', [id], one=True)
    if not armario:
        return "Armário não encontrado.", 404
    # Adicionar verificação se existem prateleiras/gavetas vinculadas antes de excluir
    prateleiras_vinculadas = query_db('SELECT id FROM prateleiras_gavetas WHERE armario_id = ?', [id])
    if prateleiras_vinculadas:
        return "Não é possível excluir o armário pois existem prateleiras/gavetas vinculadas a ele.", 400
    execute_db('DELETE FROM armarios WHERE id = ?', [id])
    return redirect(url_for('listar_armarios', deposito_id=armario['deposito_id']))

@app.route('/armarios/<int:armario_id>/prateleiras-gavetas')
@admin_required
def listar_prateleiras_gavetas(armario_id):
    if not armario_id:
        return "ID do armário inválido.", 400
    armario = query_db('SELECT id, nome, deposito_id FROM armarios WHERE id = ?', [armario_id], one=True)
    if not armario:
        return "Armário não encontrado.", 404
    prateleiras_gavetas = query_db('SELECT id, tipo, numero, descricao FROM prateleiras_gavetas WHERE armario_id = ?', [armario_id])
    deposito = query_db('SELECT d.id, d.nome FROM depositos d JOIN armarios a ON d.id = a.deposito_id WHERE a.id = ?', [armario_id], one=True)
    return render_template('listar_prateleiras_gavetas.html', armario=armario, prateleiras_gavetas=prateleiras_gavetas, deposito=deposito, datetime=datetime)

@app.route('/armarios/<int:armario_id>/prateleiras-gavetas/adicionar', methods=['GET', 'POST'])
@admin_required
def adicionar_prateleira_gaveta(armario_id):
    armario = query_db('SELECT id, nome FROM armarios WHERE id = ?', [armario_id], one=True)
    if not armario:
        return "Armário não encontrado.", 404
    erro = None
    if request.method == 'POST':
        tipo = request.form['tipo'].upper()
        numero = request.form['numero']
        descricao = request.form['descricao']
        if not tipo:
            erro = 'O tipo (prateleira ou gaveta) é obrigatório.'
        elif not numero:
            erro = 'O número/identificação é obrigatório.'
        elif query_db('SELECT id FROM prateleiras_gavetas WHERE armario_id = ? AND tipo = ? AND numero = ?', [armario_id, tipo, numero], one=True):
            erro = f'Já existe uma {tipo} com este número neste armário.'
        else:
            execute_db('INSERT INTO prateleiras_gavetas (armario_id, tipo, numero, descricao) VALUES (?, ?, ?, ?)', [armario_id, tipo, numero, descricao])
            return redirect(url_for('listar_prateleiras_gavetas', armario_id=armario_id))
    return render_template('adicionar_prateleira_gaveta.html', armario=armario, erro=erro, datetime=datetime)

@app.route('/prateleiras-gavetas/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_prateleira_gaveta(id):
    prateleira_gaveta = query_db('SELECT id, armario_id, tipo, numero, descricao FROM prateleiras_gavetas WHERE id = ?', [id], one=True)
    if not prateleira_gaveta:
        return "Prateleira/Gaveta não encontrada.", 404
    armario = query_db('SELECT id, nome FROM armarios WHERE id = ?', [prateleira_gaveta['armario_id']], one=True)
    erro = None
    if request.method == 'POST':
        tipo = request.form['tipo'].upper()
        numero = request.form['numero']
        descricao = request.form['descricao']
        if not tipo:
            erro = 'O tipo (prateleira ou gaveta) é obrigatório.'
        elif not numero:
            erro = 'O número/identificação é obrigatório.'
        elif query_db('SELECT id FROM prateleiras_gavetas WHERE armario_id = ? AND tipo = ? AND numero = ? AND id != ?', [prateleira_gaveta['armario_id'], tipo, numero, id], one=True):
            erro = f'Já existe uma {tipo} com este número neste armário.'
        else:
            execute_db('UPDATE prateleiras_gavetas SET tipo = ?, numero = ?, descricao = ? WHERE id = ?', [tipo, numero, descricao, id])
            return redirect(url_for('listar_prateleiras_gavetas', armario_id=prateleira_gaveta['armario_id']))
    return render_template('editar_prateleira_gaveta.html', prateleira_gaveta=prateleira_gaveta, armario=armario, erro=erro, datetime=datetime)

@app.route('/prateleiras-gavetas/excluir/<int:id>')
@admin_required
def excluir_prateleira_gaveta(id):
    prateleira_gaveta = query_db('SELECT armario_id FROM prateleiras_gavetas WHERE id = ?', [id], one=True)
    if not prateleira_gaveta:
        return "Prateleira/Gaveta não encontrada.", 404
    # Adicionar verificação se existem localizações vinculadas antes de excluir (a ser implementado posteriormente)
    execute_db('DELETE FROM prateleiras_gavetas WHERE id = ?', [id])
    return redirect(url_for('listar_prateleiras_gavetas', armario_id=prateleira_gaveta['armario_id']))

@app.route('/depositos/<int:deposito_id>/itens')
@operador_required
def listar_itens_deposito(deposito_id):
    """Exibe os itens localizados em um depósito específico."""
    deposito = query_db('SELECT id, nome FROM depositos WHERE id = ?', [deposito_id], one=True)
    if not deposito:
        return "Depósito não encontrado.", 404
    itens_no_deposito = query_db('''
        SELECT
            l.produto_id,
            p.codigo,
            p.nome,
            l.quantidade
        FROM
            localizacoes l
        JOIN
            produtos p ON l.produto_id = p.id
        WHERE
            l.deposito_id = ?
    ''', [deposito_id])
    return render_template('listar_itens_deposito.html', deposito=deposito, itens=itens_no_deposito)

@app.route('/armarios/<int:armario_id>/itens')
@operador_required
def listar_itens_armario(armario_id):
    """Exibe os itens localizados em um armário específico."""
    armario = query_db('SELECT id, nome, deposito_id FROM armarios WHERE id = ?', [armario_id], one=True)
    if not armario:
        return "Armário não encontrado.", 404
    deposito = query_db('SELECT nome FROM depositos WHERE id = ?', [armario['deposito_id']], one=True)
    itens_no_armario = query_db('''
        SELECT
            l.produto_id,
            p.codigo,
            p.nome,
            l.quantidade
        FROM
            localizacoes l
        JOIN
            produtos p ON l.produto_id = p.id
        WHERE
            l.armario_id = ?
    ''', [armario_id])
    return render_template('listar_itens_armario.html', armario=armario, deposito_nome=deposito['nome'], itens=itens_no_armario)

@app.route('/prateleiras-gavetas/<int:prateleira_gaveta_id>/itens')
@operador_required
def listar_itens_prateleira_gaveta(prateleira_gaveta_id):
    """Exibe os itens localizados em uma prateleira ou gaveta específica."""
    prateleira_gaveta = query_db('SELECT id, tipo, numero, armario_id FROM prateleiras_gavetas WHERE id = ?', [prateleira_gaveta_id], one=True)
    if not prateleira_gaveta:
        return "Prateleira/Gaveta não encontrada.", 404
    armario = query_db('SELECT nome, deposito_id FROM armarios WHERE id = ?', [prateleira_gaveta['armario_id']], one=True)
    deposito = query_db('SELECT nome, id FROM depositos WHERE id = ?', [armario['deposito_id']], one=True) # Buscamos o ID também
    itens_na_prateleira_gaveta = query_db('''
        SELECT
            l.produto_id,
            p.codigo,
            p.nome,
            l.quantidade
        FROM
            localizacoes l
        JOIN
            produtos p ON l.produto_id = p.id
        WHERE
            l.prateleira_gaveta_id = ?
    ''', [prateleira_gaveta_id])
    return render_template('listar_itens_prateleira_gaveta.html', prateleira_gaveta=prateleira_gaveta, armario_nome=armario['nome'], deposito_nome=deposito['nome'], deposito_id=deposito['id'], itens=itens_na_prateleira_gaveta)

@app.route('/movimentacoes/relatorio', methods=['GET', 'POST'])
@operador_required
def relatorio_movimentacoes():
    depositos = query_db('SELECT id, nome FROM depositos')
    movimentacoes = []
    
    if request.method == 'POST':
        tipo = request.form['tipo']
        deposito_id = request.form['deposito_id']
        data_inicio = request.form['data_inicio']
        data_fim = request.form['data_fim']
        
        query = """
            SELECT 
                m.id, m.data, m.tipo, m.quantidade, 
                p.nome as produto_nome, d.nome as deposito_nome
            FROM 
                movimentacoes m
            JOIN 
                produtos p ON m.produto_id = p.id
            JOIN 
                depositos d ON m.localizacao_id = d.id  
            WHERE 
                m.tipo = ? AND m.localizacao_tipo = 'deposito' AND m.localizacao_id = ? 
                AND m.data BETWEEN ? AND ?
        """
        movimentacoes = query_db(query, [tipo, deposito_id, data_inicio, data_fim])
        
        
    return render_template(
        'relatorio_movimentacoes.html', 
        depositos=depositos, 
        movimentacoes=movimentacoes,
        datetime=datetime  # Passe o módulo datetime para o template
    )

if __name__ == '__main__':
    app.run(debug=True)